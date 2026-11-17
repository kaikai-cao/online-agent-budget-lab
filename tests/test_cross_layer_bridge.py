"""E1.4 CrossLayerBridge transport tests.

Transport-layer tests use a tiny Python JSON Lines child process to exercise
request/response correlation, serialisation, error codes, timeout, EOF,
non-zero exit and post-restart recovery gating. This child is a *transport*
fixture only -- it is never used as a proof-verification substitute. The single
real-service test (T-REAL) uses the frozen Rust ``e1_service`` binary.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

from online_budget.cross_layer_bridge import (
    BridgeEOF,
    BridgeProcessExited,
    BridgeTimeout,
    BridgeUnavailable,
    CrossLayerBridge,
    ServiceError,
)

# Minimal JSON Lines echo/control child. Modes are selected by argv so each
# test can force a specific transport fault. It speaks the frozen envelope.
_FAKE_SERVICE = textwrap.dedent(
    """
    import json, os, sys, time
    mode = sys.argv[1]
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        req = json.loads(raw)
        rid = req.get("request_id")
        method = req.get("method")
        if mode == "drop" and method == "health":
            break                      # EOF before responding
        if mode == "exit" and method == "health":
            sys.stderr.write("fake fatal\\n")
            sys.stderr.flush()
            os._exit(7)                # non-zero exit
        if mode == "slow" and method == "health":
            time.sleep(3)              # trigger client timeout
        if method == "fail":
            out = {"request_id": rid, "ok": False,
                   "error": {"code": "SCOPE_CONFLICT", "message": "nope"}}
        elif method == "health":
            out = {"request_id": rid, "ok": True, "result": {"status": "ok"}}
        elif method == "null":
            out = {"request_id": rid, "ok": True, "result": None}
        else:
            out = {"request_id": rid, "ok": True, "result": {"echo": req.get("payload")}}
        sys.stdout.write(json.dumps(out, separators=(",", ":")) + "\\n")
        sys.stdout.flush()
    """
)


def _write_fake_service(path: Path) -> None:
    path.write_text(_FAKE_SERVICE, encoding="utf-8")


def _spawn_cmd(script: Path, mode: str = "ok") -> list[str]:
    return [sys.executable, str(script), mode]


class CrossLayerBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="e14-bridge-")
        self.addCleanup(self.tmp.cleanup)
        self.script = Path(self.tmp.name) / "fake_service.py"
        _write_fake_service(self.script)

    # ---- happy path / correlation / serialisation -------------------------
    def test_t01_health_and_request_id_correlation(self):
        bridge = CrossLayerBridge(_spawn_cmd(self.script), timeout=3, startup_timeout=3)
        with bridge:
            self.assertTrue(bridge.available)
            result = bridge.health()
            self.assertEqual(result, {"status": "ok"})
            # prove-style passthrough keeps the request_id matched one-to-one.
            echoed = bridge.prove({"n": 1})
            self.assertEqual(echoed, {"echo": {"n": 1}})
        self.assertFalse(bridge.available)

    def test_t02_concurrent_requests_are_serialised(self):
        bridge = CrossLayerBridge(_spawn_cmd(self.script), timeout=5, startup_timeout=3)
        bridge.start()
        self.addCleanup(bridge.close)
        errors: list[BaseException] = []
        barrier = threading.Barrier(6)

        def worker(i: int) -> None:
            try:
                barrier.wait()
                for j in range(4):
                    result = bridge.prove({"i": i, "j": j})
                    if result != {"echo": {"i": i, "j": j}}:
                        raise AssertionError(f"crossed response: {result}")
            except BaseException as exc:  # surface into main thread
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertEqual(errors, [], f"unexpected transport errors: {errors}")

    # ---- stable error codes / null result ---------------------------------
    def test_t03_service_error_code_is_propagated(self):
        bridge = CrossLayerBridge(_spawn_cmd(self.script), timeout=3, startup_timeout=3)
        with bridge:
            with self.assertRaises(ServiceError) as ctx:
                bridge._request("fail", {})
            self.assertEqual(ctx.exception.code, "SCOPE_CONFLICT")
            # A well-formed rejection does not mark the transport unavailable.
            self.assertTrue(bridge.available)
            self.assertEqual(bridge.health(), {"status": "ok"})

    def test_t04_null_result_is_distinguished_from_failure(self):
        bridge = CrossLayerBridge(_spawn_cmd(self.script), timeout=3, startup_timeout=3)
        with bridge:
            result = bridge._request("null", {}, allow_null_result=True)
            self.assertIsNone(result)

    # ---- fault paths -------------------------------------------------------
    def test_t05_timeout_marks_unavailable_without_resend(self):
        bridge = CrossLayerBridge(_spawn_cmd(self.script, "slow"), timeout=0.5, startup_timeout=0.3)
        with self.assertRaises((BridgeTimeout, BridgeUnavailable)):
            bridge.start()
        self.assertFalse(bridge.available)

    def test_t06_eof_marks_unavailable(self):
        bridge = CrossLayerBridge(_spawn_cmd(self.script, "drop"), timeout=2, startup_timeout=2)
        with self.assertRaises((BridgeEOF, BridgeUnavailable)):
            bridge.start()
        self.assertFalse(bridge.available)

    def test_t07_nonzero_exit_marks_unavailable(self):
        bridge = CrossLayerBridge(_spawn_cmd(self.script, "exit"), timeout=2, startup_timeout=2)
        with self.assertRaises((BridgeProcessExited, BridgeUnavailable)):
            bridge.start()
        self.assertFalse(bridge.available)

    def test_t08_after_restart_submit_is_gated_until_get_operation(self):
        bridge = CrossLayerBridge(_spawn_cmd(self.script), timeout=3, startup_timeout=3)
        bridge.start()
        self.addCleanup(bridge.close)
        bridge.restart()
        self.assertTrue(bridge.must_recover)
        with self.assertRaises(BridgeUnavailable):
            bridge.submit_transition_e1({})
        # The fake child answers "null" for the get_operation method only when
        # asked via the control method name; health passthrough still succeeds.
        bridge._request("null", {}, allow_null_result=True)
        self.assertTrue(bridge.must_recover)  # gate clears only via get_operation()
        bridge.get_operation(
            operation_id="op-1",
            binding_digest="sha256:" + "0" * 64,
            metering_quote_digest="sha256:" + "0" * 64,
        )
        self.assertFalse(bridge.must_recover)
        self.assertEqual(bridge.prove({"after": True}), {"echo": {"after": True}})

    def test_t10_start_does_not_bypass_recovery_gate_after_uncertain_submit(self):
        """An uncertain submit arms the gate; start() must not clear it.

        Only a successful get_operation() may clear the gate, regardless of
        whether the caller used start() or restart() to obtain a new process.
        """

        class DropFirstSubmit(CrossLayerBridge):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.drop_next_submit = True

            def _request_once(self, method, payload, *, timeout=None, allow_null_result=False):
                if method == "submit_transition_e1" and self.drop_next_submit:
                    self.drop_next_submit = False
                    self.mark_unavailable("simulated lost submit response")
                    raise BridgeTimeout("simulated lost submit response")
                return super()._request_once(
                    method, payload, timeout=timeout, allow_null_result=allow_null_result
                )

        bridge = DropFirstSubmit(_spawn_cmd(self.script), timeout=3, startup_timeout=3)
        bridge.start()
        self.addCleanup(bridge.close)
        self.assertFalse(bridge.must_recover)  # fresh bridge: normal ops allowed

        with self.assertRaises(BridgeTimeout):
            bridge.submit_transition_e1({"op": "x"})
        self.assertFalse(bridge.available)
        self.assertTrue(bridge.must_recover)  # uncertain submit armed the gate

        # Reconnect via start() (NOT restart()) -- gate must survive.
        bridge.start()
        self.assertTrue(bridge.available)
        self.assertTrue(bridge.must_recover)
        with self.assertRaises(BridgeUnavailable):
            bridge.submit_transition_e1({"op": "y"})

        # Only a successful get_operation() clears the gate.
        bridge.get_operation(
            operation_id="op-x",
            binding_digest="sha256:" + "0" * 64,
            metering_quote_digest="sha256:" + "0" * 64,
        )
        self.assertFalse(bridge.must_recover)
        self.assertEqual(
            bridge.submit_transition_e1({"op": "z"}),
            {"echo": {"op": "z"}},
        )

    # ---- no secrets in requests -------------------------------------------
    def test_t09_request_payload_has_no_private_key_fields(self):
        captured: list[str] = []

        class CapturingBridge(CrossLayerBridge):
            def _request(self, method, payload, **kwargs):  # type: ignore[override]
                captured.append(json.dumps(payload, sort_keys=True))
                return {"captured": True}

        bridge = CapturingBridge(_spawn_cmd(self.script), timeout=3, startup_timeout=3)
        bridge.prove({"budget_id": "abc", "cost": 20})
        joined = " ".join(captured)
        self.assertNotIn("private", joined.lower())
        self.assertNotIn("signing_key", joined.lower())

    # ---- real service smoke (proof generation is real Halo2) ---------------
    @unittest.skipUnless(
        Path(__file__).resolve().parents[1].joinpath(
            "experiments", "d11_3_c_coordinator", "target", "debug", "e1_service.exe"
        ).exists(),
        "e1_service binary not built",
    )
    def test_treal_real_service_health_prove_and_restart(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        root = Path(__file__).resolve().parents[1]
        exe = root / "experiments" / "d11_3_c_coordinator" / "target" / "debug" / "e1_service.exe"

        def pub_b64(n: int) -> str:
            key = Ed25519PrivateKey.from_private_bytes(bytes([n] * 32))
            raw = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            import base64

            return base64.b64encode(raw).decode()

        import base64

        with tempfile.TemporaryDirectory(prefix="e14-real-") as d:
            db = str(Path(d) / "db.sqlite")
            cfg = Path(d) / "cfg.json"
            cfg.write_text(
                json.dumps(
                    {
                        "db_path": db,
                        "issuer_id": "issuer-e14-test",
                        "issuer_public_key_b64": pub_b64(7),
                        "executor_public_keys": {"executor-e14-test": pub_b64(9)},
                        "coordinator_key_id": "d11-coordinator-v1",
                        "coordinator_signing_key_b64": base64.b64encode(bytes([3] * 32)).decode(),
                        "coordinator_public_keys": {"d11-coordinator-v1": pub_b64(3)},
                    }
                ),
                encoding="utf-8",
            )
            bridge = CrossLayerBridge([str(exe), str(cfg)], timeout=60, startup_timeout=60)
            with bridge:
                self.assertEqual(bridge.health()["status"], "ok")
                fp = lambda n: n.to_bytes(32, "little").hex()
                witness = {
                    "budget_id": fp(101),
                    "period_id": fp(7),
                    "quota": 100,
                    "cost": 20,
                    "u_old": 0,
                    "u_new": 20,
                    "slack": 80,
                    "r_old": fp(11),
                    "r_new": fp(13),
                    "nf_secret": fp(17),
                    "policy": fp(1),
                }
                result = bridge.prove(witness)
                self.assertEqual(len(result["instance"]), 8)
                self.assertGreater(len(result["proof_b64"]), 100)
                bridge.restart()
                self.assertTrue(bridge.must_recover)
                self.assertIsNone(
                    bridge.get_operation(
                        operation_id="missing",
                        binding_digest="sha256:" + "0" * 64,
                        metering_quote_digest="sha256:" + "0" * 64,
                    )
                )
                self.assertFalse(bridge.must_recover)


if __name__ == "__main__":
    unittest.main(verbosity=2)
