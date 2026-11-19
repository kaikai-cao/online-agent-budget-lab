"""Cross-service identity binding (review round 3, blocking fix).

The witness must register intents only for its configured service allow-list,
and the verifier must bind the SIGNING service (usage.source_id) to the service
the witness registered (execution.service_id). A legitimate signature from
service B must NOT be accepted as the metering record for an execution that
the witness registered for service A.

Attacks act on REAL records: a genuinely B-signed UsageEvent is submitted for
an A-registered execution event. Verifier internals are never manipulated.
"""
import _base  # noqa: F401
import tempfile
import unittest
from pathlib import Path

from r24.metering import MeteringObserver
from r24.models import (
    UsageEvent, UsageStatus, Verdict, derive_private_key, verify_payload,
)
from r24.tool_service import ToolService
from r24.verifier import VerifyContext, charged_total, verify_scheme
from r24.witness import EventWitness


class TestServiceIdentityBinding(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="r24-bind-")
        wd = Path(self._tmp.name)
        seed = 20300101
        self.w_key = derive_private_key(seed, "witness")
        self.a_key = derive_private_key(seed, "service_A")
        self.b_key = derive_private_key(seed, "service_B")
        self.o_key = derive_private_key(seed, "observer")
        self.pubkeys = {
            "A": self.a_key.public_key(), "B": self.b_key.public_key(),
            "witness": self.w_key.public_key(), "observer": self.o_key.public_key(),
        }
        self.witness = EventWitness(wd / "w.sqlite3", self.w_key, ["A", "B"])
        self.svc_a = ToolService("A", wd / "a.sqlite3", self.a_key)
        self.svc_b = ToolService("B", wd / "b.sqlite3", self.b_key)
        self.observer = MeteringObserver("observer-01", wd / "o.sqlite3", self.o_key)

    def tearDown(self):
        self._tmp.cleanup()

    def _register_for(self, svc: str) -> str:
        eid = f"run-x:{svc}:op1:att0"
        self.witness.register_intent(
            "run-x", svc, "op1", "att0", eid, "sha256:req-op1-att0", "t-001"
        )
        for st in ("DISPATCHED", "MEASURED", "FINALIZED"):
            self.assertTrue(self.witness.advance_status(eid, st))
        return eid

    def _verify(self, usage_events):
        out = {}
        for sch in ("A", "B", "C"):
            ctx = VerifyContext(
                usage_events=usage_events, service_pubkeys=self.pubkeys,
                execution_events=(self.witness.all_events() if sch in ("B", "C") else None),
                witness_pubkey=(self.pubkeys["witness"] if sch in ("B", "C") else None),
                observations=(self.observer.all_observations() if sch == "C" else None),
                observer_pubkey=(self.pubkeys["observer"] if sch == "C" else None),
            )
            res = verify_scheme(sch, ctx)
            out[sch] = (res, charged_total(res, ctx))
        return out

    def test_b_signed_usage_cannot_match_a_registered_execution(self):
        """A B-signed, valid usage record must not settle an A-registered event."""
        eid = self._register_for("A")  # witness: A was intended to execute eid
        forged = UsageEvent(
            event_id=eid, run_id="run-x", operation_id="op1", attempt_id="att0",
            usage=300, unit="unit", status=UsageStatus.MEASURED.value, source_id="B",
        ).sign(self.b_key)  # validly signed by B (not a forgery of A's key)
        self.assertTrue(verify_payload(
            self.pubkeys["B"], forged.signature, forged.signed_payload()
        ))

        out = self._verify([forged])
        for sch in ("B", "C"):
            with self.subTest(scheme=sch):
                res, total = out[sch]
                links = [r for r in res
                         if r.verdict == Verdict.INVALID_EVENT_LINKAGE.value]
                self.assertEqual(len(links), 1,
                                 "scheme with witness must cross-check service identity")
                self.assertEqual(links[0].detail["witness"], ("run-x", "op1", "att0", "A"))
                self.assertEqual(links[0].detail["usage"], ("run-x", "op1", "att0", "B"))
                self.assertEqual(total, 0, "mismatched-source usage must NOT be billed")

        # Scheme A has NO witness, so it cannot know which service was registered;
        # it is honestly blind to this attack (not claiming detection).
        res_a, total_a = out["A"]
        self.assertFalse(any(r.verdict == Verdict.INVALID_EVENT_LINKAGE.value
                             for r in res_a))
        self.assertEqual(total_a, 300)

    def test_witness_rejects_unlisted_service_id(self):
        with self.assertRaises(ValueError):
            self.witness.register_intent(
                "run-y", "C", "op1", "att0", "run-y:C:op1:att0",
                "sha256:req", "t-001",
            )
        self.assertEqual(self.witness.event_count(), 0,
                         "rejected registration must not write the witness DB")

    def test_matching_service_identity_is_not_rejected(self):
        """No false positive: B-signed usage for a B-registered event is fine."""
        eid = self._register_for("B")
        ue = UsageEvent(
            event_id=eid, run_id="run-x", operation_id="op1", attempt_id="att0",
            usage=300, unit="unit", status=UsageStatus.MEASURED.value, source_id="B",
        ).sign(self.b_key)
        self.observer.observe(event_id=eid, observed_usage=300)
        out = self._verify([ue])
        for sch in ("B", "C"):
            with self.subTest(scheme=sch):
                res, total = out[sch]
                self.assertFalse(any(
                    r.verdict == Verdict.INVALID_EVENT_LINKAGE.value for r in res
                ))
                self.assertEqual(total, 300)


if __name__ == "__main__":
    unittest.main(verbosity=2)
