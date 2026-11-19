"""T7 flagship control: service reports 100 while actually consuming 250.

A (self-report) and B (witness without numeric observation) MUST be blind.
Only C (independent metering observation) detects USAGE_MISMATCH.
This test guards the central claim: witness registers intent, NOT consumption
truth. Do not let this regress into 'B proves the number is real'.
"""
import _base  # noqa: F401
import unittest

from r24.scenarios import TRIALS, run_trial


class TestFalseMetering(unittest.TestCase):
    def test_t7_only_c_detects_numeric_lie(self):
        for t in range(TRIALS):
            with self.subTest(trial=t):
                rec = run_trial("T7", t)
                # A and B: blind to the numeric lie. No finding; both bill the
                # reported (false) 100 for A + honest 200 for B = 300.
                self.assertEqual(rec.schemes["A"]["verdict_names"], [])
                self.assertEqual(rec.schemes["B"]["verdict_names"], [])
                self.assertEqual(rec.schemes["A"]["charged_total"], 300)
                self.assertEqual(rec.schemes["B"]["charged_total"], 300)
                self.assertTrue(rec.schemes["A"]["settleable"])
                self.assertTrue(rec.schemes["B"]["settleable"])
                # C: detects mismatch on the A op; that op is not billed (only
                # B's honest 200 remains), and the trial is not settleable.
                self.assertIn("USAGE_MISMATCH", rec.schemes["C"]["verdict_names"])
                self.assertEqual(rec.schemes["C"]["charged_total"], 200)
                self.assertFalse(rec.schemes["C"]["settleable"])
                # explicit reason fields
                mismatch = [r for r in rec.schemes["C"]["verdicts"]
                            if r["verdict"] == "USAGE_MISMATCH"]
                self.assertTrue(any(r["detail"].get("claimed_usage") == 100
                                    and r["detail"].get("observed_usage") == 250
                                    for r in mismatch))


if __name__ == "__main__":
    unittest.main(verbosity=2)
