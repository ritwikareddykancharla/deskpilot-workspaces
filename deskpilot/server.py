"""HTTP Server & AWS CloudFront `/api/*` Lambda Origin Handler for DeskPilot."""
from __future__ import annotations

import base64
import json
import mimetypes
import os
import platform
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlparse

from .vdi_control_plane import DeskPilotControlPlane

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT_DIR / "web"
DOCS_DIR = ROOT_DIR / "docs"

CONTROL_PLANE = DeskPilotControlPlane()

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def route_api_request(
    method: str,
    path: str,
    query: Dict[str, str],
    body: Dict[str, Any],
    request_id: str = "local",
) -> Tuple[int, Dict[str, Any]]:
    """Pure router shared by local HTTP server and AWS Lambda `/api/*` origin behind CloudFront."""
    try:
        if method == "GET" and path == "/api/health":
            workspaces = CONTROL_PLANE.list_workspaces_health()
            chain = CONTROL_PLANE.ledger.verify_chain_integrity()
            return 200, {
                "status": "ok",
                "service": "deskpilot-workspaces",
                "delivery": os.environ.get("DESKPILOT_DELIVERY", "cloudfront-s3-oac + lambda-api-origin"),
                "aws_region": os.environ.get("AWS_REGION", "us-west-2"),
                "bedrock_model": os.environ.get("DESKPILOT_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0"),
                "python_version": platform.python_version(),
                "request_id": request_id,
                "workspaces_count": len(workspaces),
                "sqlite_audit_chain_valid": chain["valid"],
                "sqlite_audit_rows": chain["checked_rows"],
            }

        if method == "GET" and path == "/api/state":
            snap = CONTROL_PLANE.get_state_snapshot()
            snap["request_id"] = request_id
            return 200, snap

        if method == "POST" and path in ("/api/stream/inject-degradation", "/api/workspace/inject-fault"):
            ws_id = str(body.get("workspace_id") or body.get("desktop_id") or "ws-dev-python").strip()
            fault_type = str(body.get("fault_type") or "runaway_debug_logs").strip()
            out = CONTROL_PLANE.inject_degradation(desktop_id=ws_id, fault_type=fault_type)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path in ("/api/stream/proactive-heal", "/api/workspace/remediate"):
            ws_id = str(body.get("workspace_id") or body.get("desktop_id") or "ws-dev-python").strip()
            out = CONTROL_PLANE.proactive_heal(desktop_id=ws_id)
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/desktop/collaborate":
            ws_id = body.get("workspace_id")
            os_variant = str(body.get("os_variant") or ws_id or "ws-dev-python").strip()
            task_prompt = str(body.get("task_prompt") or "").strip()
            if not task_prompt:
                return 400, {"error": "task_prompt is required"}
            allow_elevated = bool(body.get("allow_elevated", False))
            out = CONTROL_PLANE.collaborate_on_desktop(
                os_variant=os_variant,
                task_prompt=task_prompt,
                allow_elevated=allow_elevated,
                workspace_id=str(ws_id).strip() if ws_id else None,
            )
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/sandbox/exec":
            ws_id = str(body.get("workspace_id") or "ws-dev-python").strip()
            command = str(body.get("command") or "").strip()
            if not command:
                return 400, {"error": "command is required"}
            allow_elevated = bool(body.get("allow_elevated", False))
            out = CONTROL_PLANE.execute_sandbox_command(
                workspace_id=ws_id,
                command=command,
                allow_elevated=allow_elevated,
            )
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/reset":
            CONTROL_PLANE.reset()
            return 200, {
                "status": "reset_complete",
                "service": "deskpilot-workspaces",
                "request_id": request_id,
            }

        return 404, {"error": f"Unknown API route: {method} {path}"}
    except KeyError as exc:
        return 404, {"error": str(exc)}
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except Exception as exc:
        return 500, {"error": str(exc)}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """AWS Lambda Function URL handler mounted behind Amazon CloudFront `/api/*` origin."""
    req_ctx = event.get("requestContext") or {}
    method = ((req_ctx.get("http") or {}).get("method") or event.get("httpMethod") or "GET").upper()
    raw_path = event.get("rawPath") or event.get("path") or "/"
    query_params = {k: str(v) for k, v in (event.get("queryStringParameters") or {}).items() if v is not None}
    req_id = getattr(context, "aws_request_id", "cloudfront-api")

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": CORS_HEADERS, "body": ""}

    if raw_path.startswith("/api/"):
        body: Dict[str, Any] = {}
        raw_body = event.get("body")
        if raw_body:
            if event.get("isBase64Encoded") and isinstance(raw_body, str):
                raw_body = base64.b64decode(raw_body).decode("utf-8")
            body = json.loads(raw_body) if isinstance(raw_body, str) else dict(raw_body)
        status, payload = route_api_request(method, raw_path, query_params, body, request_id=req_id)
        return {
            "statusCode": status,
            "headers": {
                **CORS_HEADERS,
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
            },
            "body": json.dumps(payload, default=str),
        }

    target = WEB_DIR / ("index.html" if raw_path in ("/", "") else raw_path.lstrip("/"))
    if not target.is_file() and raw_path.endswith(".svg"):
        target = DOCS_DIR / Path(raw_path).name
    if target.is_file():
        ctype = mimetypes.guess_type(str(target))[0] or "text/html; charset=utf-8"
        return {
            "statusCode": 200,
            "headers": {**CORS_HEADERS, "Content-Type": ctype},
            "body": target.read_text(encoding="utf-8"),
        }
    return {
        "statusCode": 404,
        "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps({"error": "Not found", "path": raw_path}),
    }


class LocalDeskPilotHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

        if path.startswith("/api/"):
            status, payload = route_api_request("GET", path, query, {}, request_id="local-dev")
            raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        candidate = (WEB_DIR / rel).resolve()
        if not candidate.is_file() and path.endswith(".svg"):
            candidate = (DOCS_DIR / Path(path).name).resolve()
        if not candidate.is_file():
            candidate = WEB_DIR / "index.html"

        data = candidate.read_bytes()
        ctype = mimetypes.guess_type(str(candidate))[0] or "text/html"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        body = json.loads(raw_body) if raw_body.strip() else {}
        status, payload = route_api_request("POST", parsed.path, {}, body, request_id="local-dev")
        raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run_local_server(port: int = 3098) -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", port), LocalDeskPilotHandler)
    print(f"DeskPilot POSIX Workspace Studio running at http://localhost:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    port_num = int(os.environ.get("PORT", "3098"))
    run_local_server(port=port_num)
