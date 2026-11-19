"""T5: ingress observation lost, but service executed+reported.

A correct scheme must NOT silently treat a missing observer record as
"nothing happened" / "complete". P2/P3 return UNCERTAIN; P0/P1 (no independent
observation in their evidence stack) still report COVERED — this is the
discriminating property this scenario is designed to surface.
"""
import _base  # noqa: F401
import unittest

from r24p2.scenarios import run_trial


class TestObserverFailure(unittest.TestCase):
    def test_service_executed_and_reported(self):
        for t in range(3):
            rec = run_trial("T5", t)
            for sch in ("P2", "P3"):
                gt = rec.schemes[sch]["ground_truth"][0]
                self.assertTrue(gt["service_executed"])
                self.assertEqual(rec.schemes[sch]["observable_summary"]["submissions"], 1)
                self.assertEqual(
                    rec.schemes[sch]["observable_summary"]["ingress_observations"], 0,
                    "observer record must be absent in T5")

    def test_p2_p3_return_uncertain(self):
        for t in range(3):
            rec = run_trial("T5", t)
            for sch in ("P2", "P3"):
                results = {v["result"] for v in rec.schemes[sch]["verdicts"]}
                self.assertIn("UNCERTAIN", results, sch)
                self.assertNotIn("COVERED", results, sch)

    def test_p0_p1_remain_covered(self):
        for t in range(3):
            rec = run_trial("T5", t)
            for sch in ("P0", "P1"):
                results = {v["result"] for v in rec.schemes[sch]["verdicts"]}
                self.assertEqual(results, {"COVERED"}, sch)


if __name__ == "__main__":
    unittest.main(verbosity=2)
