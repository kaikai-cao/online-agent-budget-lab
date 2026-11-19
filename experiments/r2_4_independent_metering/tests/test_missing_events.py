"""T2 service under-reporting + T3 coordinator deletion.

Both are event-completeness failures. Scheme A (ordinary signed metering) is
expected to be BLIND; B/C must detect MISSING_USAGE_EVENT.
"""
import _base  # noqa: F401
import unittest

from r24.scenarios import TRIALS, run_trial


class TestMissingEvents(unittest.TestCase):
    def _check(self, scenario: str):
        for t in range(TRIALS):
            with self.subTest(scenario=scenario, trial=t):
                rec = run_trial(scenario, t)
                # A is blind: no finding, still bills only what it saw (300)
                self.assertNotIn("MISSING_USAGE_EVENT", rec.schemes["A"]["verdict_names"])
                self.assertEqual(rec.schemes["A"]["charged_total"], 300)
                # B/C detect the missing usage event
                self.assertIn("MISSING_USAGE_EVENT", rec.schemes["B"]["verdict_names"])
                self.assertIn("MISSING_USAGE_EVENT", rec.schemes["C"]["verdict_names"])
                self.assertFalse(rec.schemes["B"]["settleable"])
                self.assertFalse(rec.schemes["C"]["settleable"])

    def test_t2_service_under_reporting(self):
        self._check("T2")

    def test_t3_deleted_metering_record(self):
        self._check("T3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
