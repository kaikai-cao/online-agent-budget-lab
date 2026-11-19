"""T8 uncertain state: registered but never settled -> must NOT bill as zero."""
import _base  # noqa: F401
import unittest

from r24.scenarios import TRIALS, run_trial


class TestUncertainState(unittest.TestCase):
    def test_t8_uncertain_not_zero_settled(self):
        for t in range(TRIALS):
            with self.subTest(trial=t):
                rec = run_trial("T8", t)
                # A: blind (no witness) -> would silently bill 300 and settle.
                self.assertEqual(rec.schemes["A"]["verdict_names"], [])
                self.assertTrue(rec.schemes["A"]["settleable"])
                # B/C: flag INCOMPLETE and refuse settlement. Crucially, the
                # missing record is NOT treated as 'zero consumption settled'.
                for s in ("B", "C"):
                    self.assertIn("INCOMPLETE_EXECUTION_STATUS", rec.schemes[s]["verdict_names"])
                    self.assertFalse(rec.schemes[s]["settleable"])
                # the uncertain witness event has status UNCERTAIN
                uncertain = [e for e in rec.execution_events if e["status"] == "UNCERTAIN"]
                self.assertEqual(len(uncertain), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
