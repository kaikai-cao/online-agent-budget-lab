"""E1.9-B / B.1+B.2 -- STANDALONE PROCESS end-to-end test (real Windows).

This is the strongest integration evidence: it launches the Journal Service as
a SEPARATE OS PROCESS (``python -m online_budget.journal_service_main``), then
drives it through the real Named Pipe from this (client) process.  The OS caller
identity is therefore a genuinely different process token -- not a simulated
identity and not the same-thread self-connection.

Environment-gated by E1B_REAL_PIPE=1 (needs Named Pipe + process-token access).
Real multi-account ACL DENIAL is still documented as an admin-dependent item in
the implementation report; this test uses the current account for both sides.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.journal_identity import current_process_identity
from online_budget.journal_ipc import NamedPipeClient

from _e1b_helpers import make_config, sha, write_service_config_json


@unittest.skipUnless(os.environ.get("E1B_REAL_PIPE") == "1", "gated by E1B_REAL_PIPE=1")
class StandaloneProcessCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.ident = current_process_identity()
        self.jkey = Ed25519PrivateKey.generate()
        self.ekey = Ed25519PrivateKey.generate()
        import uuid
        self.pipe = f"e1b-proc-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self.config, self.raw = make_config(
            base_dir=self.dir, journal_key=self.jkey, executor_key=self.ekey,
            executor_id="exec-A", os_identity=self.ident.account,
            pipe_name=self.pipe, allowed_sid=self.ident.sid,
        )
        self.cfg_path = self.dir / "service.json"
        write_service_config_json(self.cfg_path, self.raw)

        env = dict(os.environ)
        src = str(Path(__file__).resolve().parent.parent / "src")
        env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "online_budget.journal_service_main", "--config", str(self.cfg_path)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        # Client retry loop absorbs the server start-up window.

    def _close_proc(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except Exception:  # noqa: BLE001
                    pass

    def tearDown(self) -> None:
        self._close_proc()
        self.tmp.cleanup()

    def test_P07_standalone_process_roundtrip(self):
        client = NamedPipeClient(self.pipe, connect_retries=100)
        resp = client.call("verify_integrity", {})
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(resp["result"]["verified_entries"], 0)

        intent = {
            "operation_id": "op-proc-1", "executor_id": "exec-A",
            "envelope": {
                "operation_id": "op-proc-1", "binding_digest": sha("a"),
                "executor_id": "exec-A",
            },
        }
        r2 = client.call("append_intent", intent)
        self.assertTrue(r2["ok"], r2)
        self.assertEqual(r2["result"]["entry"]["executor_id"], "exec-A")
        self.assertEqual(r2["result"]["entry"]["phase"], "INTENT")

        r3 = client.call("verify_integrity", {})
        self.assertEqual(r3["result"]["verified_entries"], 1)

    def test_P08_standalone_process_restart_restores_history(self):
        client = NamedPipeClient(self.pipe, connect_retries=100)
        intent = {
            "operation_id": "op-proc-r", "executor_id": "exec-A",
            "envelope": {
                "operation_id": "op-proc-r", "binding_digest": sha("a"),
                "executor_id": "exec-A",
            },
        }
        self.assertTrue(client.call("append_intent", intent)["ok"])

        # Stop the service process and start a fresh one on the SAME config.
        self._close_proc()
        self.proc = None
        env = dict(os.environ)
        src = str(Path(__file__).resolve().parent.parent / "src")
        env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "online_budget.journal_service_main", "--config", str(self.cfg_path)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        client2 = NamedPipeClient(self.pipe, connect_retries=100)
        resp = client2.call("verify_integrity", {})
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(resp["result"]["verified_entries"], 1)


if __name__ == "__main__":
    unittest.main()
