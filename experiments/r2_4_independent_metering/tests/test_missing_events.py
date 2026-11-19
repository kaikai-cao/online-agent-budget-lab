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
        # T2: the service never submitted -> service DB has only 1 usage row.
        for t in range(TRIALS):
            rec = run_trial("T2", t)
            self.assertEqual(len(rec.service_db_usage_events), 1)
            self.assertEqual(rec.coordinator_deleted_event_ids, [])

    def test_t3_coordinator_deletes_from_aggregation_input(self):
        self._check("T3")
        # T3 (distinct from T2): service DB KEEPS both signed usage rows,
        # coordinator drops one from the input it submits to the verifier.
        for t in range(TRIALS):
            rec = run_trial("T3", t)
            self.assertEqual(len(rec.service_db_usage_events), 2,
                             "service DB must retain the real metering record")
            self.assertEqual(len(rec.coordinator_submitted_usage_events), 1)
            self.assertEqual(len(rec.coordinator_deleted_event_ids), 1)
            dropped = rec.coordinator_deleted_event_ids[0]
            in_db = {u["event_id"] for u in rec.service_db_usage_events}
            submitted = {u["event_id"] for u in rec.coordinator_submitted_usage_events}
            self.assertIn(dropped, in_db)
            self.assertNotIn(dropped, submitted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
