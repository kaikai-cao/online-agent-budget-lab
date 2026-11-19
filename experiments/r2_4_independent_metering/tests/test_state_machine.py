"""State-machine enforcement tests (independent-review blocking fix).

Guards:
  * illegal jumps rejected, including REGISTERED -> FINALIZED and DISPATCHED ->
    FINALIZED (skipping MEASURED);
  * on rejection the DB row (status AND signature) is byte-identical;
  * FINALIZED is irreversible (no outgoing transition);
  * UNCERTAIN -> FINALIZED bypass is illegal; only UNCERTAIN -> CORRECTED ->
    FINALIZED is legal;
  * undefined status strings rejected;
  * repeated terminal transition rejected.
"""
import _base  # noqa: F401
import json
import tempfile
import unittest
from pathlib import Path

from r24.models import ExecStatus, derive_private_key
from r24.witness import EventWitness


def _fresh_witness(wd: Path) -> EventWitness:
    return EventWitness(wd / "w.db", derive_private_key(11, "witness"), ["A"])


def _snapshot(w: EventWitness, eid: str):
    evs = {e.event_id: e for e in w.all_events()}
    e = evs[eid]
    return (e.status, e.witness_signature)


class TestStateMachineEnforcement(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.wd = Path(self._tmp.name)
        self.w = _fresh_witness(self.wd)
        self.eid = self.w.register_intent(
            "run", "A", "op", "att", "e1", "sha256:req", "t-001"
        ).event_id  # REGISTERED

    def tearDown(self):
        self._tmp.cleanup()

    def test_illegal_jump_registered_to_finalized_rejected_no_db_change(self):
        before = _snapshot(self.w, self.eid)
        self.assertFalse(self.w.advance_status(self.eid, ExecStatus.FINALIZED.value))
        self.assertEqual(_snapshot(self.w, self.eid), before,
                         "rejected transition must leave status+signature unchanged")

    def test_illegal_jump_dispatched_to_finalized_rejected(self):
        self.assertTrue(self.w.advance_status(self.eid, ExecStatus.DISPATCHED.value))
        before = _snapshot(self.w, self.eid)
        self.assertFalse(self.w.advance_status(self.eid, ExecStatus.FINALIZED.value))
        self.assertEqual(_snapshot(self.w, self.eid), before)

    def test_legal_path_to_finalized_and_irreversible(self):
        for st in (ExecStatus.DISPATCHED, ExecStatus.MEASURED, ExecStatus.FINALIZED):
            self.assertTrue(self.w.advance_status(self.eid, st.value))
        final = _snapshot(self.w, self.eid)
        # no outgoing transition from FINALIZED -> any further advance rejected
        for st in (ExecStatus.DISPATCHED, ExecStatus.MEASURED,
                   ExecStatus.CORRECTED, ExecStatus.UNCERTAIN,
                   ExecStatus.FINALIZED):  # repeated terminal transition too
            self.assertFalse(self.w.advance_status(self.eid, st.value))
            self.assertEqual(_snapshot(self.w, self.eid), final,
                             "FINALIZED must be immutable and irreversible")

    def test_uncertain_bypass_to_finalized_illegal_but_corrected_path_legal(self):
        self.assertTrue(self.w.advance_status(self.eid, ExecStatus.DISPATCHED.value))
        self.assertTrue(self.w.advance_status(self.eid, ExecStatus.UNCERTAIN.value))
        before = _snapshot(self.w, self.eid)
        # bypass: UNCERTAIN -> FINALIZED must be rejected
        self.assertFalse(self.w.advance_status(self.eid, ExecStatus.FINALIZED.value))
        self.assertEqual(_snapshot(self.w, self.eid), before)
        # legal: UNCERTAIN -> CORRECTED -> FINALIZED
        self.assertTrue(self.w.advance_status(self.eid, ExecStatus.CORRECTED.value))
        self.assertTrue(self.w.advance_status(self.eid, ExecStatus.FINALIZED.value))
        self.assertEqual(_snapshot(self.w, self.eid)[0], ExecStatus.FINALIZED.value)

    def test_undefined_status_string_rejected(self):
        before = _snapshot(self.w, self.eid)
        for bogus in ("TOTALLY_MADE_UP", "", "finalized", "SETTLED"):
            self.assertFalse(self.w.advance_status(self.eid, bogus))
        self.assertEqual(_snapshot(self.w, self.eid), before)

    def test_unknown_event_rejected(self):
        self.assertFalse(self.w.advance_status("does-not-exist", ExecStatus.DISPATCHED.value))

    def test_partial_must_go_through_corrected_to_finalize(self):
        self.assertTrue(self.w.advance_status(self.eid, ExecStatus.DISPATCHED.value))
        self.assertTrue(self.w.advance_status(self.eid, ExecStatus.PARTIAL.value))
        # PARTIAL -> FINALIZED is illegal; PARTIAL -> CORRECTED -> FINALIZED legal
        before = _snapshot(self.w, self.eid)
        self.assertFalse(self.w.advance_status(self.eid, ExecStatus.FINALIZED.value))
        self.assertEqual(_snapshot(self.w, self.eid), before)
        self.assertTrue(self.w.advance_status(self.eid, ExecStatus.CORRECTED.value))
        self.assertTrue(self.w.advance_status(self.eid, ExecStatus.FINALIZED.value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
