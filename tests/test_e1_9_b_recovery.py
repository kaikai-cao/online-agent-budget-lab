"""E1.9-B / B.6 -- recovery & fault tests (unit, simulated identity).

Covers: clean restart, abnormal-stop restart, duplicate requests, same-key
different payload, journal tamper detection, and idempotency-index loss recovery
(append succeeded but fast index lost -> authoritative Journal fallback).
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.journal_service import JournalService, ServiceError, ServiceStartupError
from online_budget.journal_service_config import ServiceConfig

from _e1b_helpers import make_config, receipt_v2, result_envelope, sha, simulated_caller


class RecoveryCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.jkey = Ed25519PrivateKey.generate()
        self.ekey = Ed25519PrivateKey.generate()
        self.config, self.raw = make_config(
            base_dir=self.dir, journal_key=self.jkey, executor_key=self.ekey
        )
        self.caller = simulated_caller("TESTHOST\\exec_acct")
        self.svc = JournalService(self.config, require_os_backed=False).start()

    def tearDown(self) -> None:
        self.svc.stop()
        self.tmp.cleanup()

    @staticmethod
    def _req(method, params):
        from online_budget.journal_service import ServiceRequest
        return ServiceRequest(method=method, params=params)

    def _intent(self, op, binding=sha("a")):
        return {
            "operation_id": op, "executor_id": "exec-A",
            "envelope": {"operation_id": op, "binding_digest": binding, "executor_id": "exec-A"},
        }

    def _result(self, op, binding=sha("a"), value=1):
        rcpt = receipt_v2(
            executor_id="exec-A", operation_id=op, binding_digest=binding,
            result={"value": value}, key=self.ekey,
        )
        return {
            "operation_id": op, "executor_id": "exec-A",
            "envelope": result_envelope(
                operation_id=op, binding_digest=binding, result={"value": value}, receipt=rcpt
            ),
        }

    def test_R01_restart_restores_full_history(self):
        self.svc.handle(self._req("append_intent", self._intent("op-r1")), self.caller)
        self.svc.handle(self._req("append_result", self._result("op-r1")), self.caller)
        self.svc.stop()
        fresh = JournalService(self.config, require_os_backed=False).start()
        vi = fresh.handle(self._req("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 2)
        entry = fresh.handle(self._req("get_entry", {"operation_id": "op-r1", "phase": "RESULT"}), self.caller)
        self.assertEqual(entry["entry"]["phase"], "RESULT")
        fresh.stop()

    def test_R02_abnormal_stop_then_restart(self):
        self.svc.handle(self._req("append_intent", self._intent("op-r2")), self.caller)
        # simulate abnormal termination: drop reference without stop()
        self.svc = JournalService(self.config, require_os_backed=False).start()
        vi = self.svc.handle(self._req("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 1)

    def test_R03_duplicate_result_idempotent(self):
        self.svc.handle(self._req("append_intent", self._intent("op-r3")), self.caller)
        r1 = self.svc.handle(self._req("append_result", self._result("op-r3")), self.caller)
        r2 = self.svc.handle(self._req("append_result", self._result("op-r3")), self.caller)
        self.assertTrue(r2["idempotent"])
        self.assertEqual(r1["entry"]["seq"], r2["entry"]["seq"])
        vi = self.svc.handle(self._req("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 2)

    def test_R04_same_key_different_payload_result_conflict(self):
        self.svc.handle(self._req("append_intent", self._intent("op-r4")), self.caller)
        self.svc.handle(self._req("append_result", self._result("op-r4", value=1)), self.caller)
        with self.assertRaises(ServiceError) as ctx:
            self.svc.handle(self._req("append_result", self._result("op-r4", value=2)), self.caller)
        self.assertEqual(ctx.exception.code, "IDEMPOTENCY_CONFLICT")

    def test_R05_journal_tamper_detected_on_verify(self):
        self.svc.handle(self._req("append_intent", self._intent("op-r5")), self.caller)
        con = sqlite3.connect(self.config.journal_db_path)
        row = con.execute("SELECT entry_json FROM journal_entries WHERE seq=1").fetchone()
        entry = json.loads(row[0])
        entry["payload_digest"] = "sha256:" + "f" * 64
        con.execute("UPDATE journal_entries SET entry_json=? WHERE seq=1", (json.dumps(entry),))
        con.commit()
        con.close()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.handle(self._req("verify_integrity", {}), self.caller)
        self.assertEqual(ctx.exception.code, "INTEGRITY_FAILURE")

    def test_R06_fast_index_loss_recovered_from_signed_journal(self):
        # Append succeeds, then delete the fast index row (simulating a lost
        # idempotency write).  A retry must use the signed Journal fallback and
        # return the original entry, NOT append a duplicate.
        first = self.svc.handle(self._req("append_intent", self._intent("op-r6")), self.caller)
        con = sqlite3.connect(self.config.idempotency_db_path)
        con.execute("DELETE FROM idempotency WHERE operation_id=? AND phase='INTENT'", ("op-r6",))
        con.commit()
        con.close()
        again = self.svc.handle(self._req("append_intent", self._intent("op-r6")), self.caller)
        self.assertTrue(again["idempotent"])
        self.assertEqual(first["entry"]["seq"], again["entry"]["seq"])
        vi = self.svc.handle(self._req("verify_integrity", {}), self.caller)
        self.assertEqual(vi["verified_entries"], 1)

    def test_R07_startup_refuses_tampered_journal(self):
        self.svc.handle(self._req("append_intent", self._intent("op-r7")), self.caller)
        self.svc.stop()
        con = sqlite3.connect(self.config.journal_db_path)
        row = con.execute("SELECT entry_json FROM journal_entries WHERE seq=1").fetchone()
        entry = json.loads(row[0]); entry["entry_digest"] = "sha256:" + "0" * 64
        con.execute("UPDATE journal_entries SET entry_json=? WHERE seq=1", (json.dumps(entry),))
        con.commit(); con.close()
        with self.assertRaises(ServiceStartupError):
            JournalService(self.config, require_os_backed=False).start()


if __name__ == "__main__":
    unittest.main()
