"""T6 partial execution: two attempts (30 then 20) recorded, no under-count."""
import _base  # noqa: F401
import unittest

from r24.scenarios import TRIALS, run_trial


class TestPartialExecution(unittest.TestCase):
    def test_t6_two_attempts_billed_separately(self):
        for t in range(TRIALS):
            with self.subTest(trial=t):
                rec = run_trial("T6", t)
                self.assertEqual(len(rec.execution_events), 2)
                attempts = [e["attempt_id"] for e in rec.execution_events]
                self.assertEqual(len(set(attempts)), 2, "distinct attempt_ids")
                for s in ("A", "B", "C"):
                    self.assertEqual(rec.schemes[s]["charged_total"], 50)
                    self.assertEqual(rec.schemes[s]["verdict_names"], [])
                    self.assertTrue(rec.schemes[s]["settleable"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
