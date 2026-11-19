"""T2 bypass: P1 truly enforces (no execution); P0 has no gateway to bypass;
P2/P3 observe the unauthenticated entrance request."""
import _base  # noqa: F401
import unittest

from r24p2.scenarios import run_trial


class TestBypass(unittest.TestCase):
    def test_p1_rejects_bypass_no_execution(self):
        for t in range(3):
            rec = run_trial("T2", t)
            gt = rec.schemes["P1"]["ground_truth"][0]
            self.assertFalse(gt["service_accepted"])
            self.assertFalse(gt["service_executed"], "rejected bypass must NOT count as execution")
            self.assertFalse(gt["gateway_received"])

    def test_p2_p3_detect_bypass(self):
        for t in range(3):
            rec = run_trial("T2", t)
            for sch in ("P2", "P3"):
                results = {v["result"] for v in rec.schemes[sch]["verdicts"]}
                self.assertIn("BYPASS_DETECTED", results, sch)

    def test_p0_cannot_see_bypass(self):
        # P0 has no gateway; the direct call just executes+reports and looks normal.
        for t in range(3):
            rec = run_trial("T2", t)
            gt = rec.schemes["P0"]["ground_truth"][0]
            self.assertTrue(gt["service_executed"])
            results = {v["result"] for v in rec.schemes["P0"]["verdicts"]}
            self.assertEqual(results, {"COVERED"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
