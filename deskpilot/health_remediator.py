"""Real POSIX Workspace Health Diagnostic & Automated Remediation Engine.

Operates on real files, byte sizes, lockfiles, PIDs, octal permissions, and JSON configs
inside `/tmp/deskpilot-runtime/workspaces/<workspace_id>/`, measuring every check and fix
with `time.perf_counter()`.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List


FAULT_CATALOG: Dict[str, Dict[str, Any]] = {
    "runaway_debug_logs": {
        "fault_type": "runaway_debug_logs",
        "title": "Runaway Debug Log Disk Bloat (512 KiB Trace Flood)",
        "subsystem": "POSIX Filesystem & Log Rotation (`var/log/agent-daemon/`)",
        "runbook_id": "RB-WS-LOGROTATE-01",
        "description": "Writes a real 524,288-byte runaway debug trace log on disk; remediation gzip-archives the trace and truncates the active log.",
    },
    "zombie_pid_lockfile": {
        "fault_type": "zombie_pid_lockfile",
        "title": "Zombie Worker Lockfile (`run/workspace_worker.pid.lock`)",
        "subsystem": "POSIX Process & Lockfile Supervision (`os.kill(pid, 0)`)",
        "runbook_id": "RB-WS-PIDLOCK-02",
        "description": "Creates a stale lockfile pointing to dead PID 999991 blocking `app/healthcheck.py`; remediation verifies dead PID via `os.kill` and removes orphan lock.",
    },
    "expired_session_credentials": {
        "fault_type": "expired_session_credentials",
        "title": "Expired Session Broker Config & World-Readable Key (`0644`)",
        "subsystem": "Session Config & POSIX Key Permissions (`etc/`)",
        "runbook_id": "RB-WS-KEYPERM-03",
        "description": "Expires `etc/session_broker.json` TTL (-3600s) and weakens `signing_secret.key` to `0644`; remediation rotates HMAC token and enforces `chmod 0600`.",
    },
    "corrupted_mcp_config": {
        "fault_type": "corrupted_mcp_config",
        "title": "Corrupted `config/mcp_tools.json` Registry Syntax",
        "subsystem": "Workspace Agent Tool Configuration (`config/`)",
        "runbook_id": "RB-WS-MCPCFG-04",
        "description": "Writes truncated malformed JSON into `config/mcp_tools.json`; remediation atomically restores from verified `.bak` snapshot and runs `healthcheck.py`.",
    },
}


def inspect_workspace_health(ws_root: Path, workspace_id: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """Run real filesystem, permission, PID, and JSON diagnostics on a workspace directory."""
    t0 = time.perf_counter()
    issues: List[Dict[str, Any]] = []

    log_file = ws_root / "var" / "log" / "agent-daemon" / "worker_debug.log"
    log_bytes = log_file.stat().st_size if log_file.exists() else 0
    if log_bytes > 102400:
        issues.append(
            {
                "fault_type": "runaway_debug_logs",
                "runbook_id": "RB-WS-LOGROTATE-01",
                "summary": f"worker_debug.log size is {log_bytes:,} bytes (> 102,400 byte threshold).",
            }
        )

    lock_file = ws_root / "run" / "workspace_worker.pid.lock"
    stale_pid_detected = False
    lock_pid = None
    if lock_file.exists():
        raw_pid = lock_file.read_text(encoding="utf-8").strip()
        try:
            lock_pid = int(raw_pid)
            os.kill(lock_pid, 0)
        except (ValueError, ProcessLookupError):
            stale_pid_detected = True
        except PermissionError:
            stale_pid_detected = False

        if stale_pid_detected:
            issues.append(
                {
                    "fault_type": "zombie_pid_lockfile",
                    "runbook_id": "RB-WS-PIDLOCK-02",
                    "summary": f"Orphan lockfile {lock_file.name} references dead PID {lock_pid}.",
                }
            )

    broker_file = ws_root / "etc" / "session_broker.json"
    key_file = ws_root / "etc" / "signing_secret.key"
    now_epoch = int(time.time())
    ttl_remaining_sec = 0
    key_mode_octal = "0000"
    if key_file.exists():
        key_mode_octal = f"{stat.S_IMODE(key_file.stat().st_mode):04o}"

    broker_expired = False
    if broker_file.exists():
        try:
            b_data = json.loads(broker_file.read_text(encoding="utf-8"))
            ttl_remaining_sec = int(b_data.get("expires_at_epoch", 0)) - now_epoch
            if ttl_remaining_sec <= 0:
                broker_expired = True
        except json.JSONDecodeError:
            broker_expired = True

    if broker_expired or key_mode_octal != "0600":
        issues.append(
            {
                "fault_type": "expired_session_credentials",
                "runbook_id": "RB-WS-KEYPERM-03",
                "summary": f"Session TTL={ttl_remaining_sec}s, signing_secret.key mode={key_mode_octal} (expected >0s & 0600).",
            }
        )

    mcp_file = ws_root / "config" / "mcp_tools.json"
    mcp_valid = True
    mcp_error = ""
    if mcp_file.exists():
        try:
            json.loads(mcp_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            mcp_valid = False
            mcp_error = f"JSONDecodeError line {exc.lineno} col {exc.colno}"
    else:
        mcp_valid = False
        mcp_error = "Missing config/mcp_tools.json"

    if not mcp_valid:
        issues.append(
            {
                "fault_type": "corrupted_mcp_config",
                "runbook_id": "RB-WS-MCPCFG-04",
                "summary": f"Invalid config/mcp_tools.json ({mcp_error}).",
            }
        )

    total_bytes = sum(
        p.stat().st_size for p in ws_root.rglob("*") if p.is_file()
    )
    file_count = sum(1 for p in ws_root.rglob("*") if p.is_file())
    diag_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    return {
        "desktop_id": workspace_id,
        "workspace_id": workspace_id,
        "title": meta["title"],
        "profile": meta["profile"],
        "owner": meta["owner"],
        "purpose": meta["purpose"],
        "sandbox_path": str(ws_root),
        "status": "HEALTHY" if not issues else "DEGRADED",
        "file_count": file_count,
        "disk_usage_bytes": total_bytes,
        "active_log_bytes": log_bytes,
        "key_mode_octal": key_mode_octal,
        "session_ttl_sec": ttl_remaining_sec,
        "mcp_config_valid": mcp_valid,
        "stale_lock_present": stale_pid_detected,
        "diagnostic_ms": diag_ms,
        "issues": issues,
        "active_fault": issues[0] if issues else None,
    }


def inject_real_workspace_fault(ws_root: Path, workspace_id: str, fault_type: str) -> Dict[str, Any]:
    """Mutate real files inside `/tmp/deskpilot-runtime/workspaces/<ws_id>` to reproduce a real fault."""
    if fault_type not in FAULT_CATALOG:
        raise ValueError(f"Unknown fault_type: {fault_type}. Valid: {list(FAULT_CATALOG.keys())}")

    t0 = time.perf_counter()
    if fault_type == "runaway_debug_logs":
        log_file = ws_root / "var" / "log" / "agent-daemon" / "worker_debug.log"
        line = "[WARN] retry_loop=true stream_frame_queue_backpressure=HIGH payload=" + ("X" * 180) + "\n"
        repeats = (524288 // len(line)) + 2
        log_file.write_text((line * repeats)[:524288], encoding="utf-8")
        detail = f"Wrote {log_file.stat().st_size:,} bytes to {log_file.name}"

    elif fault_type == "zombie_pid_lockfile":
        lock_file = ws_root / "run" / "workspace_worker.pid.lock"
        lock_file.write_text("999991\n", encoding="utf-8")
        detail = "Created run/workspace_worker.pid.lock referencing dead PID 999991"

    elif fault_type == "expired_session_credentials":
        broker_file = ws_root / "etc" / "session_broker.json"
        key_file = ws_root / "etc" / "signing_secret.key"
        expired = {
            "workspace_id": workspace_id,
            "issued_at_epoch": int(time.time()) - 32400,
            "expires_at_epoch": int(time.time()) - 3600,
            "session_mode": "EXPIRED_TOKEN",
            "clipboard_egress": "DISABLED",
        }
        broker_file.write_text(json.dumps(expired, indent=2) + "\n", encoding="utf-8")
        os.chmod(key_file, 0o644)
        detail = "Set session_broker.json expires_at_epoch=-3600s and chmod 0644 on signing_secret.key"

    else:  # corrupted_mcp_config
        mcp_file = ws_root / "config" / "mcp_tools.json"
        mcp_file.write_text('{\n  "workspace_id": "' + workspace_id + '",\n  "tools": [BROKEN_JSON_EOF', encoding="utf-8")
        detail = "Wrote truncated malformed JSON to config/mcp_tools.json"

    inject_ms = round((time.perf_counter() - t0) * 1000.0, 3)
    return {
        "workspace_id": workspace_id,
        "fault_type": fault_type,
        "fault_title": FAULT_CATALOG[fault_type]["title"],
        "runbook_id": FAULT_CATALOG[fault_type]["runbook_id"],
        "detail": detail,
        "inject_ms": inject_ms,
    }


def execute_real_remediation(ws_root: Path, workspace_id: str) -> Dict[str, Any]:
    """Diagnose and remediate all active POSIX workspace faults on disk, verifying via subprocess."""
    t0 = time.perf_counter()
    bytes_before = sum(p.stat().st_size for p in ws_root.rglob("*") if p.is_file())
    actions_taken: List[Dict[str, Any]] = []

    # 1. Check & remediate runaway debug logs via real gzip compression + truncation
    log_file = ws_root / "var" / "log" / "agent-daemon" / "worker_debug.log"
    if log_file.exists() and log_file.stat().st_size > 102400:
        old_size = log_file.stat().st_size
        archive_path = ws_root / "var" / "log" / "archive" / "worker_debug.log.gz"
        raw_bytes = log_file.read_bytes()
        with gzip.open(archive_path, "wb", compresslevel=6) as gz:
            gz.write(raw_bytes)
        log_file.write_text(
            f"[INFO] log_rotated_at={int(time.time())} archived_bytes={old_size}\n",
            encoding="utf-8",
        )
        gz_size = archive_path.stat().st_size
        new_log_size = log_file.stat().st_size
        actions_taken.append(
            {
                "fault_type": "runaway_debug_logs",
                "runbook_id": "RB-WS-LOGROTATE-01",
                "before": f"worker_debug.log={old_size:,} B",
                "after": f"worker_debug.log={new_log_size:,} B + archive.gz={gz_size:,} B",
            }
        )

    # 2. Check & remediate zombie PID lockfile after verifying PID does not exist via os.kill(pid, 0)
    lock_file = ws_root / "run" / "workspace_worker.pid.lock"
    if lock_file.exists():
        raw_pid = lock_file.read_text(encoding="utf-8").strip()
        is_dead = False
        try:
            os.kill(int(raw_pid), 0)
        except (ValueError, ProcessLookupError):
            is_dead = True
        if is_dead:
            lock_file.unlink()
            actions_taken.append(
                {
                    "fault_type": "zombie_pid_lockfile",
                    "runbook_id": "RB-WS-PIDLOCK-02",
                    "before": f"lockfile present for dead PID {raw_pid}",
                    "after": "orphan lockfile unlinked after os.kill(pid, 0) ProcessLookupError check",
                }
            )

    # 3. Check & remediate expired session config and permissive key file mode
    broker_file = ws_root / "etc" / "session_broker.json"
    key_file = ws_root / "etc" / "signing_secret.key"
    now_epoch = int(time.time())
    key_mode = stat.S_IMODE(key_file.stat().st_mode) if key_file.exists() else 0
    ttl_rem = -1
    if broker_file.exists():
        try:
            b_obj = json.loads(broker_file.read_text(encoding="utf-8"))
            ttl_rem = int(b_obj.get("expires_at_epoch", 0)) - now_epoch
        except json.JSONDecodeError:
            ttl_rem = -1

    if ttl_rem <= 0 or key_mode != 0o600:
        old_mode_str = f"{key_mode:04o}"
        new_token = hmac.new(
            b"deskpilot-local-broker-key",
            f"{workspace_id}:{now_epoch}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        fresh_cfg = {
            "workspace_id": workspace_id,
            "issued_at_epoch": now_epoch,
            "expires_at_epoch": now_epoch + 28800,
            "session_token_sha256": new_token[:32],
            "session_mode": "POSIX_CONFINED_SANDBOX",
            "clipboard_egress": "DISABLED",
        }
        broker_file.write_text(json.dumps(fresh_cfg, indent=2) + "\n", encoding="utf-8")
        os.chmod(key_file, 0o600)
        verified_mode = f"{stat.S_IMODE(key_file.stat().st_mode):04o}"
        actions_taken.append(
            {
                "fault_type": "expired_session_credentials",
                "runbook_id": "RB-WS-KEYPERM-03",
                "before": f"TTL={ttl_rem}s, key_mode={old_mode_str}",
                "after": f"TTL=+28800s, key_mode={verified_mode}",
            }
        )

    # 4. Check & remediate corrupted MCP JSON configuration via atomic backup swap
    mcp_file = ws_root / "config" / "mcp_tools.json"
    bak_file = ws_root / "config" / "mcp_tools.json.bak"
    mcp_broken = False
    mcp_err = ""
    try:
        json.loads(mcp_file.read_text(encoding="utf-8"))
    except Exception as exc:
        mcp_broken = True
        mcp_err = str(exc)

    if mcp_broken and bak_file.exists():
        tmp_restore = ws_root / "config" / "mcp_tools.json.tmp"
        tmp_restore.write_text(bak_file.read_text(encoding="utf-8"), encoding="utf-8")
        os.replace(tmp_restore, mcp_file)
        parsed = json.loads(mcp_file.read_text(encoding="utf-8"))
        actions_taken.append(
            {
                "fault_type": "corrupted_mcp_config",
                "runbook_id": "RB-WS-MCPCFG-04",
                "before": f"JSON parse error ({mcp_err})",
                "after": f"Atomically restored {len(parsed.get('tools', []))} MCP tool definitions",
            }
        )

    # If workspace had no injected faults, still run real healthcheck verification
    py_bin = sys.executable or "python3"
    proc = subprocess.run(
        [py_bin, "app/healthcheck.py"],
        cwd=str(ws_root),
        shell=False,
        capture_output=True,
        text=True,
        timeout=4.0,
    )
    verified = proc.returncode == 0
    bytes_after = sum(p.stat().st_size for p in ws_root.rglob("*") if p.is_file())
    remediation_ms = round((time.perf_counter() - t0) * 1000.0, 3)

    if not actions_taken:
        actions_taken.append(
            {
                "fault_type": "preventive_health_verification",
                "runbook_id": "RB-WS-VERIFY-00",
                "before": "Workspace nominal prior to audit",
                "after": f"app/healthcheck.py exit_code={proc.returncode} ({proc.stdout.strip()})",
            }
        )

    return {
        "workspace_id": workspace_id,
        "actions_taken": actions_taken,
        "bytes_before": bytes_before,
        "bytes_after": bytes_after,
        "bytes_freed": max(0, bytes_before - bytes_after),
        "remediation_ms": remediation_ms,
        "healthcheck_verified": verified,
        "healthcheck_stdout": proc.stdout.strip(),
        "healthcheck_exit_code": proc.returncode,
    }
