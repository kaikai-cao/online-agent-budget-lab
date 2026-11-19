"""T3: service executed but submitted no report.

Crux: a gateway forward receipt proves traversal, NOT service execution. P1 can
flag an evidence gap (MISSING_EVIDENCE) but must NOT claim COVERED. P0 has no
anchor at all and detects nothing. P2/P3 have independent ingress corroboration.
"""
import _base  # noqa: F401
import unittest

from r24p2.scenarios import run_trial


class TestMissingReport(unittest.TestCase):
    def test_ground_truth_executed_but_no_submission(self):
        for t in range(3):
            rec = run_trial("T3", t)
            for sch in ("P0", "P1", "P2", "P3"):
                gt = rec.schemes[sch]["ground_truth"][0]
                self.assertTrue(gt["service_executed"])
                self.assertEqual(rec.schemes[sch]["observable_summary"]["submissions"], 0)

    def test_p0_blind(self):
        for t in range(3):
            rec = run_trial("T3", t)
            self.assertEqual(rec.schemes["P0"]["verdicts"], [])

    def test_p1_p2_p3_flag_missing_never_covered(self):
        for t in range(3):
            rec = run_trial("T3", t)
            for sch in ("P1", "P2", "P3"):
                results = {v["result"] for v in rec.schemes[sch]["verdicts"]}
                self.assertIn("MISSING_EVIDENCE", results, sch)
                self.assertNotIn("COVERED", results, "forward receipt != execution")

    def test_gt_never_in_verifier_input(self):
        # Structural: the observable evidence build path excludes GT fields.
        from r24p2.models import assert_no_ground_truth
        from r24p2.scenarios import _build_world, _evidence
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(prefix="r24p2-iso-") as d:
            w = _build_world("P3", Path(d), 7)
            obs = _evidence(w)
            assert_no_ground_truth(obs)  # must not raise
            self.assertFalse(hasattr(obs, "ground_truth"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
