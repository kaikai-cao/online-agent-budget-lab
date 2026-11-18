"""E2.2 — Journal crash recovery experiment tests.

Covers:
  * raw-data integrity (F1–F4 valid counts, barrier confirmation, three-domain
    states, receipt verification, F2 repeat effect, F3/F4 original identity);
  * test-only barrier/wrapper semantics (channel barrier fires only after a
    successful named IPC call; controlled gate writes an independent durable
    effect before the RESULT hook);
  * nothing here modifies production code or E1.9/E2.1 artifacts.
"""

from __future__ import annotations

import csv
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
import sys  # noqa: E402
for _p in (str(REPO / "src"), str(REPO / "tests"),
           str(REPO / "experiments" / "e2_2_journal_crash_recovery")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from e2_2_worker import BarrierChannel, ControlledGate, RESULT  # noqa: E402
from online_budget.journal_client import JournalClient  # noqa: E402

RUN = REPO / "experiments" / "e2_2_journal_crash_recovery" / "results" / "run-001"
FIELDS = [
    "scenario", "trial_id", "operation_id", "worker_pid", "worker_exit_code",
    "crash_point_confirmed", "journal_intent_count", "journal_result_count",
    "execution_store_record_exists", "external_effect_count_before_retry",
    "external_effect_count_after_retry", "retry_returned",
    "receipt_signature_valid", "receipt_identical_to_original",
    "dispatch_count_before_retry", "dispatch_count_after_retry",
    "recovery_classification", "error_code",
]


def _load_records() -> list[dict[str, Any]]:
    path = RUN / "trials.csv"
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        for key in ("crash_point_confirmed", "execution_store_record_exists",
                    "retry_returned", "receipt_signature_valid"):
            row[key] = str(row.get(key, "")).lower() == "true"
        for key in ("journal_intent_count", "journal_result_count",
                    "external_effect_count_before_retry", "external_effect_count_after_retry",
                    "dispatch_count_before_retry", "dispatch_count_after_retry",
                    "worker_exit_code"):
            try:
                row[key] = int(row[key])
            except (ValueError, TypeError):
                row[key] = -1
    return rows


class RawDataIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = _load_records()

    def test_00_raw_present(self):
        self.assertTrue(self.rows, f"no run-001 data at {RUN}")

    def test_01_ten_trials_per_scenario(self):
        for sc in ("F1", "F2", "F3", "F4"):
            subset = [r for r in self.rows if r["scenario"] == sc]
            self.assertEqual(len(subset), 10, f"{sc} must have 10 trials")

    def test_02_all_crash_points_confirmed_at_barrier(self):
        for r in self.rows:
            self.assertTrue(r["crash_point_confirmed"], f"{r['trial_id']} not confirmed")
            self.assertNotEqual(r["worker_pid"], 0)
            self.assertNotEqual(r["recovery_classification"], "INVALID")

    def test_03_f1_intent_only_then_continues(self):
        for r in [x for x in self.rows if x["scenario"] == "F1"]:
            self.assertEqual(r["journal_intent_count"], 1)
            self.assertEqual(r["journal_result_count"], 0)
            self.assertFalse(r["execution_store_record_exists"])
            self.assertEqual(r["external_effect_count_before_retry"], 0)
            self.assertEqual(r["external_effect_count_after_retry"], 1)
            self.assertEqual(r["recovery_classification"], "CONTINUED_AFTER_INTENT")

    def test_04_f2_uncertain_repeat_effect(self):
        for r in [x for x in self.rows if x["scenario"] == "F2"]:
            self.assertEqual(r["journal_intent_count"], 1)
            self.assertEqual(r["journal_result_count"], 0)
            self.assertEqual(r["external_effect_count_before_retry"], 1)
            self.assertEqual(r["external_effect_count_after_retry"], 2)
            self.assertEqual(r["recovery_classification"], "REPEATED_EFFECT_UNCERTAIN")

    def test_05_f3_recovers_original_without_redispatch(self):
        for r in [x for x in self.rows if x["scenario"] == "F3"]:
            self.assertEqual(r["journal_intent_count"], 1)
            self.assertEqual(r["journal_result_count"], 1)
            self.assertFalse(r["execution_store_record_exists"])
            self.assertEqual(r["external_effect_count_before_retry"], 1)
            self.assertEqual(r["external_effect_count_after_retry"], 1)
            self.assertTrue(r["receipt_signature_valid"])
            self.assertEqual(str(r["receipt_identical_to_original"]).lower(), "true")
            self.assertEqual(r["recovery_classification"], "RECOVERED_ORIGINAL_FROM_JOURNAL")

    def test_06_f4_local_idempotent_without_redispatch(self):
        for r in [x for x in self.rows if x["scenario"] == "F4"]:
            self.assertEqual(r["journal_intent_count"], 1)
            self.assertEqual(r["journal_result_count"], 1)
            self.assertTrue(r["execution_store_record_exists"])
            self.assertEqual(r["external_effect_count_before_retry"], 1)
            self.assertEqual(r["external_effect_count_after_retry"], 1)
            self.assertTrue(r["receipt_signature_valid"])
            self.assertEqual(str(r["receipt_identical_to_original"]).lower(), "true")
            self.assertEqual(r["recovery_classification"], "LOCAL_IDEMPOTENT_RETURN")

    def test_07_f3_f4_receipt_valid_and_dispatch_flat(self):
        for r in self.rows:
            if r["scenario"] in ("F3", "F4"):
                self.assertTrue(r["receipt_signature_valid"])
                self.assertEqual(r["dispatch_count_before_retry"], r["dispatch_count_after_retry"])


class WrapperSemantics(unittest.TestCase):
    def test_10_barrier_channel_fires_only_after_ok_named_method(self):
        fired: list[str] = []

        class FakeReal:
            def __init__(self, ok=True):
                self.ok = ok

            def call(self, method, params):
                return {"ok": self.ok, "result": {}} if self.ok else {
                    "ok": False, "error": {"code": "X", "message": "x"}}

        import e2_2_worker as w
        original = w._barrier
        try:
            w._barrier = lambda point, m, r: fired.append(point)
            ch = BarrierChannel(FakeReal(ok=True), "F1", "m", "r")
            ch.call("append_intent", {})
            self.assertEqual(fired, ["F1_AFTER_INTENT_BEFORE_DISPATCH"])
            fired.clear()
            ch.call("verify_integrity", {})
            self.assertEqual(fired, [])
            ch3 = BarrierChannel(FakeReal(ok=True), "F3", "m", "r")
            ch3.call("append_result", {})
            self.assertEqual(fired, ["F3_AFTER_RESULT_BEFORE_LOCAL_COMMIT"])
            fired.clear()
            chfail = BarrierChannel(FakeReal(ok=False), "F1", "m", "r")
            chfail.call("append_intent", {})
            self.assertEqual(fired, [])
        finally:
            w._barrier = original

    def test_11_effect_counter_is_independent_and_durable(self):
        with tempfile.TemporaryDirectory() as td:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from online_budget.execution_store import ExecutionStore
            from _e1b_helpers import receipt_v2

            db = Path(td) / "exec.sqlite3"
            eff = str(Path(td) / "external.sqlite3")
            store = ExecutionStore(db)
            con0 = sqlite3.connect(eff)
            con0.execute("CREATE TABLE dispatch_events(id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, created_at REAL NOT NULL)")
            con0.execute("CREATE TABLE effects(id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, invoice_id TEXT NOT NULL, created_at REAL NOT NULL)")
            con0.commit()
            con0.close()

            key = Ed25519PrivateKey.generate()
            gate = ControlledGate(key=key, store=store, effect_db=eff,
                                  scenario="NONE", marker_path=None, release_path=None,
                                  operation_id="op-x", executor_id="exec-e22")

            def dispatch_args():
                pass

            class Pending:
                binding_digest = "sha256:" + "a" * 64
                binding = {}

            result = gate.execute_e1(
                pending_execution=Pending(), store_con=None,
                before_store_commit=None,
            )
            self.assertTrue(result["payload"]["status"] == "SUCCEEDED")
            con = sqlite3.connect(eff)
            n_eff = con.execute("SELECT COUNT(*) FROM effects WHERE operation_id='op-x'").fetchone()[0]
            n_disp = con.execute("SELECT COUNT(*) FROM dispatch_events WHERE operation_id='op-x'").fetchone()[0]
            con.close()
            self.assertEqual(n_eff, 1)
            self.assertEqual(n_disp, 1)
            self.assertEqual(gate.dispatch_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
