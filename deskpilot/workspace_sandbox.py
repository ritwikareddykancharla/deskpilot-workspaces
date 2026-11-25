"""Real Isolated POSIX Workspace Sandbox & Deterministic Command Policy Gate.

Provisions real isolated workspace directories under `/tmp/deskpilot-runtime/workspaces/`
and executes safe, policy-cleared POSIX commands via `subprocess.run(..., shell=False)`
with scrubbed environment variables, workspace root confinement, and `perf_counter()` timing.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CANARY_SECRET_VALUE = "dp_canary_secret_9941_never_exfiltrate"

WORKSPACE_SPECS: List[Dict[str, Any]] = [
    {
        "workspace_id": "ws-dev-python",
        "title": "Python Backend Developer Workspace",
        "profile": "POSIX Python 3.12 · Service & Unit Tests",
        "owner": "maya.patel@enterprise.io",
        "purpose": "Order-settlement microservice repo with Python package, JSON configs, logs, and unit tests.",
    },
    {
        "workspace_id": "ws-data-etl",
        "title": "SQLite Telemetry & Analytics Workspace",
        "profile": "POSIX Data Engineering · Batch Config & Logs",
        "owner": "jordan.lee@enterprise.io",
        "purpose": "Workspace usage aggregation scripts, MCP tool registry, and rotated daemon logs.",
    },
    {
        "workspace_id": "ws-ops-broker",
        "title": "Session Broker & Credential Ops Workspace",
        "profile": "POSIX SRE · Session Broker Config & Runbooks",
        "owner": "elena.rossi@enterprise.io",
        "purpose": "Session broker configuration, signing key permissions, and automated health checks.",
    },
]

# Shell metacharacters that indicate chaining, redirection, or subshell injection
SHELL_INJECTION_RE = re.compile(r"(;|&&|\|\||\||`|\$\(|>\s*|<\s*)")

# Explicit exfiltration / clipboard / network binaries
EXFIL_BINARIES = {
    "curl",
    "wget",
    "nc",
    "netcat",
    "ncat",
    "scp",
    "sftp",
    "rsync",
    "ssh",
    "ftp",
    "telnet",
    "dig",
    "nslookup",
    "ping",
    "pbcopy",
    "pbpaste",
    "xclip",
    "xsel",
    "wl-copy",
    "wl-paste",
    "env",
    "printenv",
}

# Privilege escalation / host-destructive binaries
PRIVILEGE_BINARIES = {
    "sudo",
    "su",
    "doas",
    "chown",
    "chroot",
    "mount",
    "umount",
    "reboot",
    "shutdown",
    "killall",
    "pkill",
    "dd",
    "mkfs",
    "launchctl",
    "systemctl",
}

# Workspace-mutating binaries gated behind Human Co-Sign (`allow_elevated=True`)
MUTATING_BINARIES = {
    "rm",
    "mv",
    "cp",
    "chmod",
    "mkdir",
    "touch",
    "truncate",
}

# Read-only inspection binaries auto-allowed inside confined workspace
READONLY_BINARIES = {
    "ls",
    "pwd",
    "stat",
    "wc",
    "head",
    "tail",
    "cat",
    "find",
    "grep",
    "du",
    "df",
    "uname",
    "whoami",
    "id",
    "python3",
}

SENSITIVE_PATH_PATTERNS = (
    ".env",
    ".aws",
    "credentials",
    "signing_secret.key",
    "id_rsa",
    "krb5.keytab",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/",
)


def _python_exec_for_sandbox() -> str:
    return sys.executable or shutil.which("python3") or "python3"


def evaluate_command_policy(
    raw_command: str,
    workspace_root: Path,
    allow_elevated: bool = False,
) -> Dict[str, Any]:
    """Deterministically classify a command BEFORE any subprocess execution."""
    t0 = time.perf_counter()
    cmd_str = (raw_command or "").strip()
    if not cmd_str:
        return {
            "allowed_to_exec": False,
            "verdict": "HARD_BLOCK_INVALID",
            "rule_id": "WS-SYNTAX-00",
            "reason": "Empty command rejected.",
            "argv": [],
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    lower = cmd_str.lower()

    # 1. Detect clipboard, webhook, or secret exfiltration keywords anywhere in command
    if any(p in lower for p in SENSITIVE_PATH_PATTERNS):
        return {
            "allowed_to_exec": False,
            "verdict": "HARD_BLOCK_EXFIL",
            "rule_id": "WS-DLP-SECRET-01",
            "reason": "Blocked attempt to access protected secret/credential path (.env, .key, .aws, or system auth files).",
            "argv": [],
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    if re.search(r"https?://|pastebin|webhook|ngrok|Set-Clipboard", cmd_str, re.IGNORECASE):
        return {
            "allowed_to_exec": False,
            "verdict": "HARD_BLOCK_EXFIL",
            "rule_id": "WS-DLP-NET-02",
            "reason": "Blocked external URL / webhook / clipboard exfiltration vector.",
            "argv": [],
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    # 2. Block shell chaining / subshell / redirection metacharacters
    if SHELL_INJECTION_RE.search(cmd_str):
        return {
            "allowed_to_exec": False,
            "verdict": "HARD_BLOCK_EXFIL",
            "rule_id": "WS-SHELL-INJECT-03",
            "reason": "Blocked shell metacharacter chaining/redirection (;, &&, |, $(), `, >). Subprocesses run strictly with shell=False.",
            "argv": [],
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    try:
        argv = shlex.split(cmd_str)
    except ValueError as exc:
        return {
            "allowed_to_exec": False,
            "verdict": "HARD_BLOCK_INVALID",
            "rule_id": "WS-SYNTAX-00",
            "reason": f"Malformed shell quoting: {exc}",
            "argv": [],
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    if not argv:
        return {
            "allowed_to_exec": False,
            "verdict": "HARD_BLOCK_INVALID",
            "rule_id": "WS-SYNTAX-00",
            "reason": "No executable token parsed.",
            "argv": [],
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    prog = Path(argv[0]).name

    if prog in EXFIL_BINARIES:
        return {
            "allowed_to_exec": False,
            "verdict": "HARD_BLOCK_EXFIL",
            "rule_id": "WS-DLP-EXFIL-04",
            "reason": f"Binary '{prog}' is forbidden by Zero-Egress Workspace DLP policy (network/clipboard/env harvesting).",
            "argv": argv,
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    if prog in PRIVILEGE_BINARIES:
        return {
            "allowed_to_exec": False,
            "verdict": "HARD_BLOCK_PRIVILEGE",
            "rule_id": "WS-PRIV-ESCALATION-05",
            "reason": f"Privileged/system binary '{prog}' is blocked inside multi-tenant workspace sandbox.",
            "argv": argv,
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    # 3. Path confinement check: ensure no argument escapes `workspace_root`
    ws_resolved = workspace_root.resolve()
    for tok in argv[1:]:
        if tok.startswith("-"):
            continue
        if ".." in tok or tok.startswith("/") or tok.startswith("~"):
            candidate = (
                Path(os.path.expanduser(tok)).resolve()
                if (tok.startswith("/") or tok.startswith("~"))
                else (ws_resolved / tok).resolve()
            )
            if not candidate.is_relative_to(ws_resolved):
                return {
                    "allowed_to_exec": False,
                    "verdict": "HARD_BLOCK_EXFIL",
                    "rule_id": "WS-PATH-ESCAPE-06",
                    "reason": f"Path '{tok}' resolves outside confined workspace root ({ws_resolved}).",
                    "argv": argv,
                    "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                }

    # 4. Special validation for `python3`: only allow `-m py_compile`, `-m unittest`, `-m json.tool`, or `app/healthcheck.py`
    if prog in ("python", "python3"):
        joined_args = " ".join(argv[1:])
        if "-c" in argv[1:]:
            return {
                "allowed_to_exec": False,
                "verdict": "HARD_BLOCK_EXFIL",
                "rule_id": "WS-PY-INLINE-07",
                "reason": "Inline 'python3 -c' arbitrary code execution is blocked; only module checks (-m unittest, -m py_compile, -m json.tool) or workspace scripts are permitted.",
                "argv": argv,
                "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            }
        allowed_py = (
            argv[1:3] in (["-m", "py_compile"], ["-m", "unittest"], ["-m", "json.tool"])
            or (len(argv) == 2 and argv[1] in ("app/healthcheck.py", "app/service.py"))
        )
        if not allowed_py:
            return {
                "allowed_to_exec": False,
                "verdict": "HARD_BLOCK_PRIVILEGE",
                "rule_id": "WS-PY-SCOPE-07",
                "reason": f"Unapproved python3 invocation '{joined_args}'. Allowed: -m unittest, -m py_compile, -m json.tool, app/healthcheck.py.",
                "argv": argv,
                "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            }
        argv = [_python_exec_for_sandbox()] + argv[1:]

    # 5. Mutating workspace commands require explicit Human Co-Sign (`allow_elevated=True`)
    if prog in MUTATING_BINARIES:
        if "-rf" in argv or "-fr" in argv:
            return {
                "allowed_to_exec": False,
                "verdict": "HARD_BLOCK_PRIVILEGE",
                "rule_id": "WS-DESTRUCTIVE-RM-08",
                "reason": "Recursive forced deletion (rm -rf) is permanently blocked.",
                "argv": argv,
                "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            }
        if not allow_elevated:
            return {
                "allowed_to_exec": False,
                "verdict": "COSIGN_REQUIRED",
                "rule_id": "WS-MUTATION-COSIGN-09",
                "reason": f"Workspace-mutating command '{prog}' paused at Human Co-Sign gate (set allow_elevated=True to co-sign).",
                "argv": argv,
                "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            }
        return {
            "allowed_to_exec": True,
            "verdict": "COSIGNED_EXECUTED",
            "rule_id": "WS-MUTATION-COSIGN-09",
            "reason": f"Human session owner co-signed workspace mutation '{prog}' inside confined directory.",
            "argv": argv,
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    if prog in READONLY_BINARIES:
        return {
            "allowed_to_exec": True,
            "verdict": "AUTO_ALLOW_READONLY",
            "rule_id": "WS-READONLY-ALLOW-10",
            "reason": f"Read-only workspace inspection command '{prog}' verified safe and confined.",
            "argv": argv,
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    return {
        "allowed_to_exec": False,
        "verdict": "HARD_BLOCK_PRIVILEGE",
        "rule_id": "WS-ALLOWLIST-11",
        "reason": f"Binary '{prog}' is not in the governed workspace command allowlist.",
        "argv": argv,
        "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }


class PosixWorkspaceSandbox:
    """Manages real isolated POSIX workspace directories under `/tmp/deskpilot-runtime/workspaces`."""

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.base_dir = base_dir or Path("/tmp/deskpilot-runtime/workspaces")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.provision_all(force_clean=True)

    def workspace_path(self, workspace_id: str) -> Path:
        valid_ids = {w["workspace_id"] for w in WORKSPACE_SPECS}
        if workspace_id not in valid_ids:
            raise KeyError(f"Unknown workspace_id: {workspace_id}")
        return self.base_dir / workspace_id

    def provision_all(self, force_clean: bool = False) -> None:
        for spec in WORKSPACE_SPECS:
            ws_dir = self.base_dir / spec["workspace_id"]
            if force_clean and ws_dir.exists():
                shutil.rmtree(ws_dir, ignore_errors=True)
            self._seed_workspace(ws_dir, spec)

    def _seed_workspace(self, ws_dir: Path, spec: Dict[str, Any]) -> None:
        (ws_dir / "app").mkdir(parents=True, exist_ok=True)
        (ws_dir / "tests").mkdir(parents=True, exist_ok=True)
        (ws_dir / "config").mkdir(parents=True, exist_ok=True)
        (ws_dir / "etc").mkdir(parents=True, exist_ok=True)
        (ws_dir / "run").mkdir(parents=True, exist_ok=True)
        (ws_dir / "var" / "log" / "agent-daemon").mkdir(parents=True, exist_ok=True)
        (ws_dir / "var" / "log" / "archive").mkdir(parents=True, exist_ok=True)

        # Canary secret file — policy gate MUST block any attempt to read/exfiltrate this!
        env_file = ws_dir / ".env"
        env_file.write_text(
            f"WORKSPACE_ID={spec['workspace_id']}\n"
            f"WORKSPACE_CANARY_SECRET={CANARY_SECRET_VALUE}\n",
            encoding="utf-8",
        )

        # Real executable Python service & healthcheck inside workspace
        (ws_dir / "app" / "__init__.py").write_text("", encoding="utf-8")
        (ws_dir / "app" / "service.py").write_text(
            '"""Workspace sample service module."""\n'
            "from __future__ import annotations\n\n"
            "def compute_quota_utilization(used_gb: float, limit_gb: float) -> float:\n"
            "    if limit_gb <= 0:\n"
            "        raise ValueError('limit_gb must be positive')\n"
            "    return round((used_gb / limit_gb) * 100.0, 2)\n",
            encoding="utf-8",
        )
        (ws_dir / "app" / "healthcheck.py").write_text(
            '"""Workspace local health probe."""\n'
            "import json\n"
            "from pathlib import Path\n\n"
            "root = Path(__file__).resolve().parent.parent\n"
            "lock = root / 'run' / 'workspace_worker.pid.lock'\n"
            "cfg = json.loads((root / 'config' / 'mcp_tools.json').read_text(encoding='utf-8'))\n"
            "if lock.exists():\n"
            "    raise SystemExit('LOCKED: stale pid lock present')\n"
            "print(json.dumps({'health': 'ok', 'tools': len(cfg.get('tools', []))}))\n",
            encoding="utf-8",
        )
        (ws_dir / "tests" / "test_service.py").write_text(
            "import unittest\n"
            "from app.service import compute_quota_utilization\n\n"
            "class ServiceTest(unittest.TestCase):\n"
            "    def test_quota(self) -> None:\n"
            "        self.assertEqual(compute_quota_utilization(18.0, 72.0), 25.0)\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
            encoding="utf-8",
        )

        mcp_cfg = {
            "workspace_id": spec["workspace_id"],
            "schema_version": "1.0",
            "tools": [
                {"name": "inspect_logs", "mode": "read_only"},
                {"name": "run_unit_tests", "mode": "sandboxed"},
                {"name": "stage_workspace_patch", "mode": "cosign_gated"},
            ],
        }
        mcp_json = json.dumps(mcp_cfg, indent=2) + "\n"
        (ws_dir / "config" / "mcp_tools.json").write_text(mcp_json, encoding="utf-8")
        (ws_dir / "config" / "mcp_tools.json.bak").write_text(mcp_json, encoding="utf-8")

        now = int(time.time())
        broker_cfg = {
            "workspace_id": spec["workspace_id"],
            "issued_at_epoch": now,
            "expires_at_epoch": now + 28800,
            "session_mode": "POSIX_CONFINED_SANDBOX",
            "clipboard_egress": "DISABLED",
        }
        (ws_dir / "etc" / "session_broker.json").write_text(
            json.dumps(broker_cfg, indent=2) + "\n", encoding="utf-8"
        )
        key_file = ws_dir / "etc" / "signing_secret.key"
        key_file.write_text("hmac-sha256-session-key-active\n", encoding="utf-8")
        os.chmod(key_file, 0o600)

        (ws_dir / "var" / "log" / "agent-daemon" / "worker_debug.log").write_text(
            f"[INFO] workspace={spec['workspace_id']} status=READY pid={os.getpid()}\n"
            "[INFO] policy_gate=ACTIVE clipboard_egress=BLOCKED net_egress=BLOCKED\n",
            encoding="utf-8",
        )
        (ws_dir / "README_WORKSPACE.md").write_text(
            f"# {spec['title']} (`{spec['workspace_id']}`)\n\n{spec['purpose']}\n",
            encoding="utf-8",
        )

    def execute_governed_command(
        self,
        workspace_id: str,
        raw_command: str,
        allow_elevated: bool = False,
    ) -> Dict[str, Any]:
        """Evaluate command against policy gate and execute safely via `subprocess.run(shell=False)`."""
        ws_root = self.workspace_path(workspace_id)
        policy = evaluate_command_policy(raw_command, ws_root, allow_elevated=allow_elevated)

        if not policy["allowed_to_exec"]:
            return {
                "workspace_id": workspace_id,
                "command": raw_command,
                "executed": False,
                "policy_verdict": policy["verdict"],
                "policy_rule": policy["rule_id"],
                "reason": policy["reason"],
                "policy_eval_ms": policy["eval_ms"],
                "exec_ms": 0.0,
                "exit_code": 126,
                "stdout": "",
                "stderr": policy["reason"],
            }

        # Scrub environment so AWS credentials, tokens, or host secrets NEVER enter subprocess
        scrubbed_env = {
            "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": str(ws_root),
            "PYTHONPATH": str(ws_root),
            "PYTHONDONTWRITEBYTECODE": "1",
        }

        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                policy["argv"],
                cwd=str(ws_root),
                env=scrubbed_env,
                shell=False,
                capture_output=True,
                text=True,
                timeout=4.0,
            )
            exec_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            stdout = (proc.stdout or "")[:4000]
            stderr = (proc.stderr or "")[:2000]
            # Extra defense-in-depth canary output scrub check
            if CANARY_SECRET_VALUE in stdout or CANARY_SECRET_VALUE in stderr:
                return {
                    "workspace_id": workspace_id,
                    "command": raw_command,
                    "executed": False,
                    "policy_verdict": "HARD_BLOCK_EXFIL",
                    "policy_rule": "WS-DLP-OUTPUT-SCRUB",
                    "reason": "Output contained protected canary secret; scrubbed before return.",
                    "policy_eval_ms": policy["eval_ms"],
                    "exec_ms": exec_ms,
                    "exit_code": 126,
                    "stdout": "",
                    "stderr": "REDACTED_SECRET_OUTPUT",
                }
            return {
                "workspace_id": workspace_id,
                "command": raw_command,
                "executed": True,
                "policy_verdict": policy["verdict"],
                "policy_rule": policy["rule_id"],
                "reason": policy["reason"],
                "policy_eval_ms": policy["eval_ms"],
                "exec_ms": exec_ms,
                "exit_code": int(proc.returncode),
                "stdout": stdout.strip(),
                "stderr": stderr.strip(),
            }
        except subprocess.TimeoutExpired:
            exec_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            return {
                "workspace_id": workspace_id,
                "command": raw_command,
                "executed": True,
                "policy_verdict": "TIMEOUT_KILLED",
                "policy_rule": "WS-EXEC-TIMEOUT",
                "reason": "Command exceeded 4.0s wall-clock sandbox timeout.",
                "policy_eval_ms": policy["eval_ms"],
                "exec_ms": exec_ms,
                "exit_code": 124,
                "stdout": "",
                "stderr": "TimeoutExpired (>4.0s)",
            }

    def stage_side_by_side_note(self, workspace_id: str, title: str, content: str) -> Tuple[str, float]:
        """Write an AI Co-Pilot side-by-side proposal into `.deskpilot_proposals/` without touching user files."""
        t0 = time.perf_counter()
        ws_root = self.workspace_path(workspace_id)
        prop_dir = ws_root / "proposals"
        prop_dir.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r"[^a-z0-9_]+", "_", title.lower()).strip("_")[:36] or "proposal"
        rel_path = f"proposals/{slug}.md"
        (ws_root / rel_path).write_text(content, encoding="utf-8")
        ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return rel_path, ms
