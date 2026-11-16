from __future__ import annotations

import ipaddress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from typing import Any
from urllib.parse import urlparse

from .auth import verify_gateway_envelope
from .errors import CoordinatorError
from .grants import LeaseRevocation, OnlineLeaseGrant

MAX_BODY_BYTES = 1_048_576


class CoordinatorHTTPServer(ThreadingHTTPServer):
    """Loopback-only HTTP server; terminate TLS at a reverse proxy for remote Gateways."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, coordinator):
        host = server_address[0]
        # D9.3.1: do not accept hostnames; validate the exact IP literal passed to bind().
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except (ValueError, TypeError):
            loopback = False
        if not loopback:
            raise ValueError(
                "built-in Coordinator HTTP server requires an explicit loopback IP literal; "
                "use a TLS reverse proxy for remote Gateways"
            )
        self.coordinator = coordinator
        super().__init__(server_address, CoordinatorRequestHandler)


class CoordinatorRequestHandler(BaseHTTPRequestHandler):
    server: CoordinatorHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Deployment logging should be configured by the caller. Never log request bodies.
        return

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            info = self.server.coordinator.inspect()
            # This unauthenticated endpoint intentionally exposes only non-secret identity/health fields.
            self._send_json(200, {
                "ok": True,
                "coordinator_id": info["coordinator_id"],
                "global_budget_id": info["global_budget_id"],
                "health": info["health"],
            })
            return
        self.close_connection = True
        self._send_json(404, {"ok": False, "error": {"code": "NOT_FOUND", "message": "unknown endpoint"}})

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in {
            "/v1/leases/register", "/v1/leases/revoke", "/v1/leases/lookup",
            "/v1/budget/consume", "/v1/budget/lookup",
        }:
            # The request body has not been consumed; close to prevent keep-alive desynchronization.
            self.close_connection = True
            self._send_json(404, {"ok": False, "error": {"code": "NOT_FOUND", "message": "unknown endpoint"}})
            return

        # Reject ambiguous framing. The built-in server does not implement chunked request bodies.
        content_lengths = self.headers.get_all("Content-Length", [])
        transfer_encodings = self.headers.get_all("Transfer-Encoding", [])
        if len(content_lengths) != 1 or transfer_encodings:
            self.close_connection = True
            self._send_json(400, {"ok": False, "error": {"code": "BAD_REQUEST", "message": "exactly one Content-Length is required; Transfer-Encoding is unsupported"}})
            return

        try:
            length = int(content_lengths[0])
        except (TypeError, ValueError):
            self.close_connection = True
            self._send_json(400, {"ok": False, "error": {"code": "BAD_REQUEST", "message": "Content-Length is invalid"}})
            return

        if length < 1:
            self.close_connection = True
            self._send_json(400, {"ok": False, "error": {"code": "BAD_REQUEST", "message": "request body length must be positive"}})
            return
        if length > MAX_BODY_BYTES:
            self.close_connection = True
            self._send_json(413, {"ok": False, "error": {"code": "PAYLOAD_TOO_LARGE", "message": "request body exceeds configured limit"}})
            return

        content_type = self.headers.get("Content-Type", "")
        media_type = content_type.split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            self.close_connection = True
            self._send_json(415, {"ok": False, "error": {"code": "UNSUPPORTED_MEDIA_TYPE", "message": "Content-Type must be application/json"}})
            return

        try:
            raw_body = self.rfile.read(length)
            if len(raw_body) != length:
                self.close_connection = True
                raise ValueError("request body is incomplete")
            envelope = json.loads(raw_body.decode("utf-8"))
            gateway_id, payload = verify_gateway_envelope(
                envelope, method="POST", path=path,
                gateway_lookup=self.server.coordinator.gateway_public_key,
            )
            result = self._dispatch(path, gateway_id, payload)
            self._send_json(200, {"ok": True, "result": result})
        except CoordinatorError as exc:
            self._send_json(exc.http_status, {"ok": False, "error": {"code": exc.code, "message": str(exc)}})
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            self.close_connection = True
            self._send_json(400, {"ok": False, "error": {"code": "BAD_REQUEST", "message": str(exc)}})
        except Exception:
            # Do not leak stack traces, key material, or database internals over HTTP.
            self._send_json(500, {"ok": False, "error": {"code": "INTERNAL_ERROR", "message": "internal Coordinator error"}})

    def _dispatch(self, path: str, gateway_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        c = self.server.coordinator
        if path == "/v1/leases/register":
            grant = OnlineLeaseGrant.from_dict(payload["grant"])
            return c.register_lease(gateway_id, grant)
        if path == "/v1/leases/revoke":
            record = LeaseRevocation.from_dict(payload["revocation"])
            return c.revoke_lease(gateway_id, record)
        if path == "/v1/leases/lookup":
            lease_id = payload["lease_id"]
            lease = c.get_lease_for_gateway(gateway_id, lease_id)
            if lease is None:
                return {"found": False}
            return {"found": True, **lease}
        if path == "/v1/budget/consume":
            grant = OnlineLeaseGrant.from_dict(payload["online_lease_grant"])
            receipt = c.consume(
                gateway_id, grant, payload["execution_grant"],
                operation_id=payload["operation_id"], request_digest=payload["request_digest"],
            )
            return receipt.as_dict()
        if path == "/v1/budget/lookup":
            receipt = c.lookup_operation(gateway_id, payload["operation_id"])
            return {"found": receipt is not None, "receipt": receipt.as_dict() if receipt else None}
        raise ValueError("unhandled endpoint")


def serve(coordinator, host: str = "127.0.0.1", port: int = 8765) -> None:
    server = CoordinatorHTTPServer((host, port), coordinator)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
