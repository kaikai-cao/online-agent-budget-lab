"""T4: distinguish a duplicate transmission from a genuinely new attempt.

P0 has no attempt tracking -> two distinct attempts collapse into one bill.
P1-P3 key by (logical_call_id, attempt_id) -> two distinct attempts kept.
"""
import _base  # noqa: F401
import unittest

from r24p2.scenarios import run_trial


class TestRetry(unittest.TestCase):
    def test_ground_truth_has_two_distinct_executions(self):
        for t in range(3):
            rec = run_trial("T4", t)
            for sch in ("P1", "P2", "P3"):
                executed = [g for g in rec.schemes[sch]["ground_truth"] if g["service_executed"]]
                self.assertEqual(len(executed), 2)
                attempts = {g["attempt_id"] for g in executed}
                self.assertEqual(attempts, {"att-1", "att-2"})

    def test_p0_merges_two_executions_into_one_bill(self):
        for t in range(3):
            rec = run_trial("T4", t)
            # P0 sees 3 submissions but all with blank attempt -> one key.
            results = rec.schemes["P0"]["verdicts"]
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["result"], "DUPLICATE_IGNORED")
            # ground truth still has 2 executions -> 1 missed by P0
            self.assertEqual(len(rec.schemes["P0"]["ground_truth"]), 2)

    def test_p1_p3_keep_attempts_distinct(self):
        for t in range(3):
            rec = run_trial("T4", t)
            for sch in ("P1", "P2", "P3"):
                results = {v["result"] for v in rec.schemes[sch]["verdicts"]}
                self.assertIn("COVERED", results, sch)
                self.assertIn("DUPLICATE_IGNORED", results, sch)
                # exactly one real duplicate ignored, one distinct attempt covered
                dups = sum(1 for v in rec.schemes[sch]["verdicts"]
                           if v["result"] == "DUPLICATE_IGNORED")
                self.assertEqual(dups, 1, sch)


if __name__ == "__main__":
    unittest.main(verbosity=2)
