"""SQLite WAL + SHA-256 Hash-Chained WORM Audit Ledger for DeskPilot."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class SQLiteAuditLedger:
    """Tamper-evident SQLite audit log stored in `/tmp/deskpilot-runtime/deskpilot_audit.db`."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_schema(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    event_kind TEXT NOT NULL,
                    command_or_target TEXT NOT NULL,
                    policy_verdict TEXT NOT NULL,
                    exit_code INTEGER NOT NULL,
                    duration_ms REAL NOT NULL,
                    prev_hash TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS remediation_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    fault_type TEXT NOT NULL,
                    bytes_before INTEGER NOT NULL,
                    bytes_after INTEGER NOT NULL,
                    detail_before TEXT NOT NULL,
                    detail_after TEXT NOT NULL,
                    remediation_ms REAL NOT NULL,
                    verified INTEGER NOT NULL,
                    bedrock_latency_ms REAL NOT NULL,
                    bedrock_tokens INTEGER NOT NULL,
                    sha256_hash TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def reset(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute("DELETE FROM audit_events")
            conn.execute("DELETE FROM remediation_runs")
            conn.commit()

    def append_event(
        self,
        workspace_id: str,
        actor: str,
        event_kind: str,
        command_or_target: str,
        policy_verdict: str,
        exit_code: int = 0,
        duration_ms: float = 0.0,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT sha256_hash, id FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = row["sha256_hash"] if row else "GENESIS_DESKPILOT_SQLITE_0000"
            next_seq = (int(row["id"]) + 1) if row else 1
            event_id = f"AUD-{next_seq:05d}"

            canonical = json.dumps(
                {
                    "event_id": event_id,
                    "timestamp": ts,
                    "workspace_id": workspace_id,
                    "actor": actor,
                    "event_kind": event_kind,
                    "command_or_target": command_or_target,
                    "policy_verdict": policy_verdict,
                    "exit_code": int(exit_code),
                    "duration_ms": round(float(duration_ms), 3),
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
            )
            digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp, workspace_id, actor, event_kind,
                    command_or_target, policy_verdict, exit_code, duration_ms,
                    prev_hash, sha256_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    ts,
                    workspace_id,
                    actor,
                    event_kind,
                    command_or_target,
                    policy_verdict,
                    int(exit_code),
                    round(float(duration_ms), 3),
                    prev_hash,
                    digest,
                ),
            )
            conn.commit()

        write_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return {
            "event_id": event_id,
            "timestamp": ts,
            "workspace_id": workspace_id,
            "actor": actor,
            "event_kind": event_kind,
            "command_or_target": command_or_target,
            "policy_verdict": policy_verdict,
            "exit_code": int(exit_code),
            "duration_ms": round(float(duration_ms), 3),
            "prev_hash": prev_hash,
            "sha256_hash": digest,
            "ledger_write_ms": write_ms,
        }

    def record_remediation(
        self,
        workspace_id: str,
        fault_type: str,
        bytes_before: int,
        bytes_after: int,
        detail_before: str,
        detail_after: str,
        remediation_ms: float,
        verified: bool,
        bedrock_latency_ms: float,
        bedrock_tokens: int,
        sha256_hash: str,
    ) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT INTO remediation_runs (
                    timestamp, workspace_id, fault_type, bytes_before, bytes_after,
                    detail_before, detail_after, remediation_ms, verified,
                    bedrock_latency_ms, bedrock_tokens, sha256_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    workspace_id,
                    fault_type,
                    int(bytes_before),
                    int(bytes_after),
                    detail_before,
                    detail_after,
                    round(float(remediation_ms), 3),
                    1 if verified else 0,
                    round(float(bedrock_latency_ms), 2),
                    int(bedrock_tokens),
                    sha256_hash,
                ),
            )
            conn.commit()

    def verify_chain_integrity(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()

        expected_prev = "GENESIS_DESKPILOT_SQLITE_0000"
        for r in rows:
            if r["prev_hash"] != expected_prev:
                return {
                    "valid": False,
                    "checked_rows": len(rows),
                    "broken_at_event": r["event_id"],
                    "verify_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                }
            canonical = json.dumps(
                {
                    "event_id": r["event_id"],
                    "timestamp": r["timestamp"],
                    "workspace_id": r["workspace_id"],
                    "actor": r["actor"],
                    "event_kind": r["event_kind"],
                    "command_or_target": r["command_or_target"],
                    "policy_verdict": r["policy_verdict"],
                    "exit_code": int(r["exit_code"]),
                    "duration_ms": round(float(r["duration_ms"]), 3),
                    "prev_hash": r["prev_hash"],
                },
                sort_keys=True,
            )
            recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if recomputed != r["sha256_hash"]:
                return {
                    "valid": False,
                    "checked_rows": len(rows),
                    "broken_at_event": r["event_id"],
                    "verify_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                }
            expected_prev = recomputed

        return {
            "valid": True,
            "checked_rows": len(rows),
            "head_sha256": expected_prev,
            "verify_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    def get_recent_events(self, limit: int = 16) -> List[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_recent_remediations(self, limit: int = 10) -> List[Dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM remediation_runs ORDER BY id DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [dict(r) for r in rows]
