"""T5 duplicate reporting: identical counted once, conflict rejected."""
import _base  # noqa: F401
import unittest

from r24.scenarios import TRIALS, run_trial


class TestDuplicateEvents(unittest.TestCase):
    def test_t5_identical_counted_once_conflict_rejected(self):
        for t in range(TRIALS):
            with self.subTest(trial=t):
                rec = run_trial("T5", t)
                for s in ("A", "B", "C"):
                    vnames = rec.schemes[s]["verdict_names"]
                    self.assertIn("DUPLICATE_USAGE_EVENT", vnames)
                    # identical duplicate of A(300) billed once; conflicting B(250)
                    # rejected (the original B=200 also suppressed by conflict) -> 300
                    self.assertEqual(rec.schemes[s]["charged_total"], 300)
                # inspect the duplicate findings themselves
                dup = [r for r in rec.schemes["A"]["verdicts"]
                       if r["verdict"] == "DUPLICATE_USAGE_EVENT"]
                kinds = {r["detail"].get("duplicate_kind") for r in dup}
                self.assertIn("identical", kinds)
                self.assertIn("conflict", kinds)

    def test_distinct_attempt_ids_are_not_deduped(self):
        # T6: two attempts with different attempt_id must both be billed (50).
        for t in range(TRIALS):
            rec = run_trial("T6", t)
            for s in ("A", "B", "C"):
                self.assertEqual(rec.schemes[s]["charged_total"], 50)
                self.assertNotIn("DUPLICATE_USAGE_EVENT", rec.schemes[s]["verdict_names"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
