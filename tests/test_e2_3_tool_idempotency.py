"""E2.3 tool-side idempotency experiment —专项测试.

Two groups:
  * RawDataIntegrity — the recorded run-001 rows match the E2.3 invariants.
  * SinkSemantics — unit-level checks of the ExternalToolSink (no processes):
      atomic dedup, same-key/different-argument conflict, key excludes args,
      request_digest recomputed from ACTUAL arguments, concurrent single effect,
      mid-transaction rollback, and the idempotency-key derivation boundary.

No production file is modified.  Does not touch E1.9 / E2.1 / E2.2 tests.
"""

from __future__ import annotations

import csv
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "experiments" / "e2_3_sink_idempotency"))

from sink import (  # noqa: E402
    ExternalToolSink,
    IDEMPOTENCY_DOMAIN,
    OUTCOME_CONFLICT,
    OUTCOME_DEDUP_HIT,
    OUTCOME_EXECUTED,
    OUTCOME_ROLLED_BACK,
    REQUEST_DOMAIN,
    sink_idempotency_key,
    sink_request_digest,
)
from online_budget.canonical import digest  # noqa: E402

RESULTS = REPO / "experiments" / "e2_3_sink_idempotency" / "results" / "run-001"
VARIANTS = ("V0", "V1", "V2")
BOOL_FIELDS = {
    "crash_point_confirmed", "execution_store_record_exists", "retry_returned",
    "receipt_signature_valid", "receipt_binding_consistent",
    "receipt_result_matches_sink",
}
INT_FIELDS = {
    "journal_intent_count", "journal_result_count",
    "sink_effect_count_before_retry", "sink_effect_count_after_retry",
    "dispatch_count_before_retry", "dispatch_count_after_retry",
}


def _load_records() -> list[dict]:
    with (RESULTS / "trials.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        for f in BOOL_FIELDS:
            row[f] = str(row.get(f, "")).strip().lower() == "true"
        for f in INT_FIELDS:
            try:
                row[f] = int(row[f])
            except (ValueError, KeyError):
                row[f] = -1
    return rows


RESULT = {"value": 42, "echo": "e23-sink-effect"}
ARGS_A = {"invoice_id": "INV-E23-SYSTEM"}
ARGS_B = {"invoice_id": "INV-E23-ATTACK"}


class RawDataIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = _load_records()

    def test_00_results_exist(self):
        self.assertTrue((RESULTS / "trials.csv").exists())
        self.assertTrue((RESULTS / "summary.json").exists())
        self.assertTrue((RESULTS / "raw.json").exists())
        self.assertTrue((RESULTS / "trials.csv").stat().st_size > 0)

    def test_01_variants_present(self):
        for v in VARIANTS:
            rows = [r for r in self.records if r["variant"] == v]
            self.assertEqual(len(rows), 10, f"{v} must have 10 trials")
            self.assertTrue(all(r["crash_point_confirmed"] for r in rows), v)
            self.assertTrue(all(r["recovery_classification"] != "INVALID" for r in rows), v)

    def test_02_real_process_kill_evidence(self):
        raw = json.loads((RESULTS / "raw.json").read_text(encoding="utf-8"))
        self.assertTrue(raw["meta"]["kill_is_real_process_termination"])
        self.assertTrue(raw["meta"]["worker_is_standalone_process"])
        self.assertTrue(raw["meta"]["journal_service_is_standalone_process"])
        self.assertTrue(raw["meta"]["sink_db_is_independent"])
        pids = {r["worker_pid"] for r in raw["records"] if r["worker_pid"] not in ("", 0)}
        self.assertGreaterEqual(len(pids), 25, "distinct worker PIDs expected")
        self.assertTrue(all(r["worker_exit_code"] not in ("",) for r in raw["records"]))

    def test_03_v0_repeats_effect(self):
        rows = [r for r in self.records if r["variant"] == "V0"]
        for r in rows:
            self.assertEqual(r["journal_intent_count"], 1)
            self.assertEqual(r["journal_result_count"], 0)
            self.assertFalse(r["execution_store_record_exists"])
            self.assertEqual(r["sink_effect_count_before_retry"], 1)
            self.assertEqual(r["sink_effect_count_after_retry"], 2)
            self.assertEqual(r["dispatch_count_after_retry"], 2)
            self.assertEqual(r["recovery_classification"], "EFFECT_REPEATED")

    def test_04_v1_suppresses_second_effect_allows_dispatch(self):
        rows = [r for r in self.records if r["variant"] == "V1"]
        for r in rows:
            self.assertEqual(r["sink_effect_count_before_retry"], 1)
            self.assertEqual(r["sink_effect_count_after_retry"], 1, "no second effect")
            self.assertEqual(r["dispatch_count_after_retry"], 2, "dispatch DID repeat")
            self.assertIn("DEDUP_HIT", r["sink_outcomes"])
            self.assertTrue(r["receipt_signature_valid"])
            self.assertTrue(r["receipt_binding_consistent"])
            self.assertTrue(r["receipt_result_matches_sink"])
            self.assertEqual(r["recovery_classification"], "SINK_DEDUP_NO_REPEAT")

    def test_05_receipt_continuity_boundary(self):
        # F2 crash: no persisted original Receipt → identity marked N/A, never True.
        raw = json.loads((RESULTS / "raw.json").read_text(encoding="utf-8"))
        for r in raw["records"]:
            self.assertEqual(r["receipt_identical_to_original"], "N/A_NO_ORIGINAL_AT_CRASH")

    def test_06_v2_conflict_rejected(self):
        rows = [r for r in self.records if r["variant"] == "V2"]
        for r in rows:
            self.assertEqual(r["sink_effect_count_before_retry"], 1)
            self.assertEqual(r["sink_effect_count_after_retry"], 1, "conflict: no new effect")
            self.assertEqual(r["dispatch_count_after_retry"], 2)
            self.assertIn("IDEMPOTENCY_KEY_CONFLICT", r["sink_outcomes"])
            self.assertEqual(r["error_code"], "IDEMPOTENCY_KEY_CONFLICT")
            self.assertEqual(r["recovery_classification"], "IDEMPOTENCY_CONFLICT_REJECTED")

    def test_07_special_checks(self):
        summary = json.loads((RESULTS / "summary.json").read_text(encoding="utf-8"))
        checks = summary["special_checks"]
        self.assertTrue(checks["concurrency"]["passed"])
        self.assertTrue(checks["rollback"]["passed"])
        self.assertEqual(checks["concurrency"]["committed_effects"], 1)
        self.assertEqual(checks["rollback"]["effect_after_retry"], 1)


class SinkSemantics(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.sink = ExternalToolSink(Path(self._tmp.name) / "sink.sqlite3")
        self.key = sink_idempotency_key(executor_id="exec-e23", operation_id="op-1")

    def tearDown(self):
        self._tmp.cleanup()

    def _dispatch(self, key=None, args=None, enabled=True, rollback_once=False, op="op-1"):
        return self.sink.dispatch(
            idempotency_key=key or self.key, operation_id=op, executor_id="exec-e23",
            tool_name="local.echo", tool_schema_hash="sha256:" + "d" * 64,
            arguments=args or ARGS_A, result=RESULT, invoice_id="INV-E23-SYSTEM",
            enabled=enabled, rollback_once=rollback_once,
        )

    def test_10_key_excludes_arguments_and_binding_digest(self):
        k1 = sink_idempotency_key(executor_id="e", operation_id="o")
        k2 = sink_idempotency_key(executor_id="e", operation_id="o")
        self.assertEqual(k1, k2, "same identity → same key regardless of arguments")
        # key is derived only from domain+executor_id+operation_id
        self.assertEqual(k1, digest({
            "domain": IDEMPOTENCY_DOMAIN, "executor_id": "e", "operation_id": "o",
        }))
        self.assertNotIn("binding_digest", k1)
        self.assertNotIn("arguments", k1)

    def test_11_request_digest_recomputed_from_actual_arguments(self):
        d_a = sink_request_digest(
            executor_id="e", operation_id="o", tool_name="t", tool_schema_hash="h",
            arguments=ARGS_A,
        )
        d_b = sink_request_digest(
            executor_id="e", operation_id="o", tool_name="t", tool_schema_hash="h",
            arguments=ARGS_B,
        )
        self.assertNotEqual(d_a, d_b, "different arguments → different request digest")
        self.assertEqual(d_a, digest({
            "domain": REQUEST_DOMAIN, "executor_id": "e", "operation_id": "o",
            "tool_name": "t", "tool_schema_hash": "h", "arguments": ARGS_A,
        }))

    def test_12_atomic_dedup_same_key_same_args(self):
        first = self._dispatch()
        self.assertEqual(first["outcome"], OUTCOME_EXECUTED)
        second = self._dispatch()
        self.assertEqual(second["outcome"], OUTCOME_DEDUP_HIT)
        self.assertEqual(second["result"], RESULT, "dedup returns ORIGINAL result")
        self.assertEqual(self.sink.effect_count("op-1"), 1)
        self.assertEqual(self.sink.dispatch_count("op-1"), 2)

    def test_13_same_key_different_args_conflict(self):
        self._dispatch(args=ARGS_A)
        resp = self._dispatch(args=ARGS_B)
        self.assertEqual(resp["outcome"], OUTCOME_CONFLICT)
        self.assertIsNone(resp["result"])
        self.assertEqual(self.sink.effect_count("op-1"), 1)
        self.assertIn(OUTCOME_CONFLICT, self.sink.outcomes("op-1"))

    def test_14_no_idempotency_repeats_effect(self):
        self._dispatch(enabled=False)
        self._dispatch(enabled=False)
        self.assertEqual(self.sink.effect_count("op-1"), 2)

    def test_15_rollback_rolls_back_key_and_effect_together(self):
        resp = self._dispatch(rollback_once=True)
        self.assertEqual(resp["outcome"], OUTCOME_ROLLED_BACK)
        self.assertFalse(self.sink.record_exists(self.key))
        self.assertEqual(self.sink.effect_count("op-1"), 0)
        # normal retry succeeds
        second = self._dispatch()
        self.assertEqual(second["outcome"], OUTCOME_EXECUTED)
        self.assertEqual(self.sink.effect_count("op-1"), 1)

    def test_16_concurrent_same_key_single_effect(self):
        n = 8
        barrier = threading.Barrier(n)

        def run():
            barrier.wait()
            try:
                self._dispatch(op="concurrent")
            except Exception:
                pass

        threads = [threading.Thread(target=run) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertEqual(self.sink.effect_count("concurrent"), 1)
        self.assertEqual(self.sink.dispatch_count("concurrent"), n)


if __name__ == "__main__":
    unittest.main(verbosity=2)
