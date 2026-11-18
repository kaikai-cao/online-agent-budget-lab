"""E1.9-B / B.2 -- IPC framing unit tests + REAL Windows Named Pipe test.

Framing tests (P01-P04) are platform independent.

The REAL Named Pipe test (P05) is environment-gated by E1B_REAL_PIPE=1 because
it depends on current-account Named Pipe + impersonation permissions.  It uses
the CURRENT process SID as the ACL allow entry and the identity mapping key, so
no administrator account setup is required; it verifies real OS identity flows
through the server and that a valid call round-trips.  True multi-account ACL
DENIAL is documented as an environment dependency in the implementation report
(with the administrator commands) and is NOT claimed as passed here.
"""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.journal_ipc import (
    IPCError,
    MAX_FRAME_BYTES,
    NamedPipeClient,
    NamedPipeServer,
    build_request,
    decode_frame,
    dispatch,
    encode_frame,
    parse_request,
    parse_response,
)
from online_budget.journal_identity import current_process_identity
from online_budget.journal_service import JournalService, ServiceRequest

from _e1b_helpers import make_config, receipt_v2, result_envelope, sha


class FramingCase(unittest.TestCase):
    def test_P01_frame_roundtrip(self):
        obj = build_request("get_head", {"a": 1})
        self.assertEqual(decode_frame(encode_frame(obj)), obj)

    def test_P02_oversize_frame_rejected(self):
        with self.assertRaises(IPCError) as ctx:
            encode_frame({"method": "m", "params": {"blob": "x" * (MAX_FRAME_BYTES + 1)}})
        self.assertEqual(ctx.exception.code, "FRAME_TOO_LARGE")

    def test_P03_bad_request_fields_rejected(self):
        with self.assertRaises(IPCError):
            parse_request({"method": "m"})  # missing params

    def test_P04_dispatch_error_never_success(self):
        # A malformed request must produce an error response, never ok=True.
        import json, struct
        raw = struct.pack(">I", len(b'{"method": 1}')) + b'{"method": 1}'
        resp = parse_response(dispatch(None, None, raw))  # type: ignore[arg-type]
        self.assertFalse(resp["ok"])
        self.assertIn("error", resp)


@unittest.skipUnless(os.environ.get("E1B_REAL_PIPE") == "1", "real Named Pipe test gated by E1B_REAL_PIPE=1")
class RealNamedPipeCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.ident = current_process_identity()
        self.jkey = Ed25519PrivateKey.generate()
        self.ekey = Ed25519PrivateKey.generate()
        import uuid
        self.config, self.raw = make_config(
            base_dir=self.dir, journal_key=self.jkey, executor_key=self.ekey,
            executor_id="exec-A", os_identity=self.ident.account,
            pipe_name=f"e1b-real-{os.getpid()}-{uuid.uuid4().hex[:8]}",
            allowed_sid=self.ident.sid,
        )
        self.svc = JournalService(self.config, require_os_backed=True).start()
        self.server = NamedPipeServer(
            pipe_name=self.config.pipe_name,
            allowed_sids=(self.ident.sid,),
            service=self.svc,
            require_os_backed=True,
        )
        self._server_errors: list[str] = []

        def _run_server():
            import traceback
            try:
                self.server.serve_forever()
            except BaseException:  # keep the test thread from swallowing the cause
                self._server_errors.append(traceback.format_exc())

        self.thread = threading.Thread(target=_run_server, daemon=True)
        self.thread.start()
        # Give the server thread time to create and publish the pipe endpoint.
        # (Real clients use NamedPipeClient's connect retry loop instead.)
        import time
        time.sleep(0.15)

    def tearDown(self) -> None:
        self.server.stop()
        self.svc.stop()
        self.tmp.cleanup()

    def test_P05_real_pipe_get_head_and_integrity(self):
        client = NamedPipeClient(self.config.pipe_name)
        resp = client.call("verify_integrity", {})
        if self._server_errors:
            self.fail("server thread error:\n" + self._server_errors[0])
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(resp["result"]["verified_entries"], 0)

    def test_P06_real_pipe_full_flow_and_identity(self):
        """A real Named Pipe round-trip for append_intent uses the OS identity."""
        client = NamedPipeClient(self.config.pipe_name)
        intent = {
            "operation_id": "op-pipe-1",
            "executor_id": "exec-A",
            "envelope": {
                "operation_id": "op-pipe-1",
                "binding_digest": sha("a"),
                "executor_id": "exec-A",
            },
        }
        resp = client.call("append_intent", intent)
        if self._server_errors:
            self.fail("server thread error:\n" + self._server_errors[0])
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(resp["result"]["entry"]["phase"], "INTENT")
        self.assertEqual(resp["result"]["entry"]["executor_id"], "exec-A")

    def test_P09_stop_unblocks_idle_server_no_client(self):
        """B-F3: with NO client connected, stop() must let serve_forever exit.

        Before B-F3, ConnectNamedPipe(handle, None) blocked forever and stop()
        only set a flag that was never re-checked until a client connected.
        """
        # setUp already started serve_forever in self.thread and no client has
        # connected.  Stop it and require the thread to exit within 3 seconds.
        self.server.stop()
        self.thread.join(timeout=3)
        self.assertFalse(
            self.thread.is_alive(),
            "serve_forever did not exit after stop() with no client connected",
        )
        if self._server_errors:
            self.fail("server thread error:\n" + self._server_errors[0])

    def test_P10_production_path_uses_impersonated_identity(self):
        """B-F4: the production server authenticates the Named Pipe CLIENT
        SECURITY CONTEXT (via=WIN32_NAMED_PIPE_IMPERSONATION), not the process
        token.  A true client SQOS level is required for this to succeed.
        """
        import uuid

        class CapturingService:
            def __init__(self, real):
                self._real = real
                self._authorizer = real._authorizer
                self.callers = []

            def handle(self, request, caller):
                self.callers.append(caller)
                return self._real.handle(request, caller)

        real_svc = JournalService(self.config, require_os_backed=True).start()
        cap = CapturingService(real_svc)
        srv = NamedPipeServer(
            pipe_name=f"e1b-imp-{os.getpid()}-{uuid.uuid4().hex[:8]}",
            allowed_sids=(self.ident.sid,), service=cap, require_os_backed=True,
            identity_mode="impersonation",
        )
        errors = []

        def _run():
            import traceback
            try:
                srv.serve_one(timeout_ms=5000)
            except BaseException:
                errors.append(traceback.format_exc())

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        import time
        time.sleep(0.15)
        try:
            client = NamedPipeClient(srv.pipe_name, connect_retries=100)
            resp = client.call("verify_integrity", {})
            t.join(timeout=3)
            self.assertFalse(errors, errors[0] if errors else "")
            self.assertTrue(resp["ok"], resp)
            self.assertEqual(len(cap.callers), 1)
            self.assertEqual(cap.callers[0].via, "WIN32_NAMED_PIPE_IMPERSONATION")
            self.assertTrue(cap.callers[0].is_os_backed)
        finally:
            srv.stop()
            real_svc.stop()


if __name__ == "__main__":
    unittest.main()
