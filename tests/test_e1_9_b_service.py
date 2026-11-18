"""E1.9-B / B.1 + B.4 + B.5 -- Journal Service core tests (unit, simulated ID).

Covers service lifecycle (startup integrity gate, restart recovery), the six
APIs, server-side Receipt v2 rejection paths, and content-sensitive persistent
idempotency.  Simulated identities are accepted via require_os_backed=False;
these are unit tests, NOT real Windows ACL acceptance tests.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.journal_service import JournalService, ServiceError, ServiceStartupError
from online_budget.journal_service_config import ServiceConfig

from _e1b_helpers import make_config, receipt_v2, result_envelope, sha, simulated_caller


class ServiceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.jkey = Ed25519PrivateKey.generate()
        self.ekey = Ed25519PrivateKey.generate()
        self.config, self.raw = make_config(
            base_dir=self.dir, journal_key=self.jkey, executor_key=self.ekey
        )
        self.account = "TESTHOST\\exec_acct"
        self.caller = simulated_caller(self.account)
        self.svc = JournalService(self.config, require_os_backed=False).start()

    def tearDown(self) -> None:
        self.svc.stop()
        self.tmp.cleanup()

    def _intent_params(self, op: str, binding: str | None = None, executor: str = "exec-A"):
        return {
            "operation_id": op,
            "executor_id": executor,
            "envelope": {
                "operation_id": op,
                "binding_digest": binding or sha("a"),
                "executor_id": executor,
            },
        }

    def _result_params(self, op: str, binding: str | None = None, result=None, version=2,
                       executor_id: str = "exec-A", receipt_overrides: dict | None = None):
        b = binding or sha("a")
        r = result if result is not None else {"value": 1}
        rcpt_params = dict(
            executor_id=executor_id, operation_id=op, binding_digest=b,
            result=r, key=self.ekey, version=version,
        )
        rcpt_params.update(receipt_overrides or {})  # may override fields INSIDE the receipt
        rcpt = receipt_v2(**rcpt_params)
        return {
            "operation_id": op,
            "executor_id": executor_id,  # outer claim (authorised via OS identity)
            "envelope": result_envelope(
                operation_id=op, binding_digest=b, result=r, receipt=rcpt
            ),
        }

    def _pair(self, op: str, value: int = 1):
        return (
            self.svc.handle(self._svc_req("append_intent", self._intent_params(op)), self.caller),
            self.svc.handle(self._svc_req("append_result", self._result_params(op, result={"value": value})), self.caller),
        )

    @staticmethod
    def _svc_req(method, params):
        from online_budget.journal_service import ServiceRequest
        return ServiceRequest(method=method, params=params)

    # -- B.1 lifecycle ----------------------------------------------------------
    def test_S01_start_and_head_empty(self):
        self.assertTrue(self.svc.is_running)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.handle(self._svc_req("get_head", {}), self.caller)
        self.assertEqual(ctx.exception.code, "EMPTY_JOURNAL")

    def test_S02_start_integrity_gate_on_tampered_db(self):
        # Append a pair, close, tamper an entry_json, then a fresh service must
        # refuse to start.
        self._pair("op-tamper")
        self.svc.stop()
        import json, sqlite3
        con = sqlite3.connect(self.config.journal_db_path)
        row = con.execute("SELECT entry_json FROM journal_entries WHERE seq=1").fetchone()
        entry = json.loads(row[0])
        entry["entry_digest"] = "sha256:" + "0" * 64  # tamper a signed field value
        con.execute("UPDATE journal_entries SET entry_json=? WHERE seq=1", (json.dumps(entry),))
        con.commit()
        con.close()
        fresh = JournalService(self.config, require_os_backed=False)
        with self.assertRaises(ServiceStartupError):
            fresh.start()

    # -- six APIs ---------------------------------------------------------------
    def test_S03_all_six_apis(self):
        intent, result = self._pair("op-all")
        self.assertEqual(intent["entry"]["phase"], "INTENT")
        self.assertEqual(result["entry"]["phase"], "RESULT")
        get_entry = self.svc.handle(
            self._svc_req("get_entry", {"operation_id": "op-all", "phase": "RESULT"}), self.caller
        )
        self.assertEqual(get_entry["entry"]["seq"], result["entry"]["seq"])
        cp = self.svc.handle(self._svc_req("get_checkpoint", {"seq": 2}), self.caller)
        self.assertEqual(cp["checkpoint"]["seq"], 2)
        head = self.svc.handle(self._svc_req("get_head", {}), self.caller)
        self.assertEqual(head["checkpoint"]["seq"], 2)
        vi = self.svc.handle(self._svc_req("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 2)

    def test_S04_result_before_intent_rejected(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.handle(self._svc_req("append_result", self._result_params("op-orphan")), self.caller)
        self.assertEqual(ctx.exception.code, "NO_INTENT")

    # -- B.4 server-side receipt rejection -------------------------------------
    def test_S05_v1_receipt_rejected_by_service(self):
        self.svc.handle(self._svc_req("append_intent", self._intent_params("op-v1")), self.caller)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.handle(
                self._svc_req("append_result", self._result_params("op-v1", version=1)), self.caller
            )
        self.assertIn(ctx.exception.code, {"RECEIPT_VERSION_UNSUPPORTED", "RECEIPT_FIELDS"})
        # no RESULT appended
        vi = self.svc.handle(self._svc_req("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 1)

    def test_S06_receipt_executor_mismatch_rejected(self):
        self.svc.handle(self._svc_req("append_intent", self._intent_params("op-em")), self.caller)
        # Outer claim stays exec-A (authorised); the Receipt's internal executor_id
        # is tampered to exec-B -> receipt-vs-INTENT binding must reject.
        params = self._result_params("op-em", receipt_overrides={"executor_id": "exec-B"})
        with self.assertRaises(ServiceError) as ctx:
            self.svc.handle(self._svc_req("append_result", params), self.caller)
        self.assertEqual(ctx.exception.code, "EXECUTOR_ID_MISMATCH")

    def test_S07_unknown_method_rejected(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.handle(self._svc_req("drop_all", {}), self.caller)
        self.assertEqual(ctx.exception.code, "UNKNOWN_METHOD")

    def test_S11_result_envelope_mismatch_rejected_no_entry(self):
        """B-F1 service path: a valid Receipt bound to result X cannot be journalled
        under an envelope claiming result Y; reject with no new Entry/Checkpoint.
        """
        self.svc.handle(self._svc_req("append_intent", self._intent_params("op-bf1")), self.caller)
        params = self._result_params("op-bf1", result={"value": 1})
        # Replace ONLY the envelope's result with a different value; the Receipt
        # stays signed/self-consistent over {"value": 1}.
        params["envelope"]["result"] = {"value": 9999}
        with self.assertRaises(ServiceError) as ctx:
            self.svc.handle(self._svc_req("append_result", params), self.caller)
        self.assertEqual(ctx.exception.code, "RESULT_ENVELOPE_MISMATCH")
        vi = self.svc.handle(self._svc_req("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 1)  # only the INTENT, no RESULT

    # -- B.5 idempotency --------------------------------------------------------
    def test_S08_same_payload_idempotent(self):
        i1 = self.svc.handle(self._svc_req("append_intent", self._intent_params("op-idem")), self.caller)
        i2 = self.svc.handle(self._svc_req("append_intent", self._intent_params("op-idem")), self.caller)
        self.assertTrue(i2["idempotent"])
        self.assertEqual(i1["entry"]["seq"], i2["entry"]["seq"])
        vi = self.svc.handle(self._svc_req("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 1)

    def test_S09_different_payload_conflict(self):
        self.svc.handle(self._svc_req("append_intent", self._intent_params("op-conf", binding=sha("a"))), self.caller)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.handle(
                self._svc_req("append_intent", self._intent_params("op-conf", binding=sha("b"))), self.caller
            )
        self.assertEqual(ctx.exception.code, "IDEMPOTENCY_CONFLICT")
        vi = self.svc.handle(self._svc_req("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 1)

    def test_S10_idempotency_persists_after_restart(self):
        first = self.svc.handle(self._svc_req("append_intent", self._intent_params("op-restart")), self.caller)
        self.svc.stop()
        fresh = JournalService(self.config, require_os_backed=False).start()
        again = fresh.handle(self._svc_req("append_intent", self._intent_params("op-restart")), self.caller)
        self.assertTrue(again["idempotent"])
        self.assertEqual(first["entry"]["seq"], again["entry"]["seq"])
        vi = fresh.handle(self._svc_req("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 1)
        fresh.stop()


if __name__ == "__main__":
    unittest.main()
