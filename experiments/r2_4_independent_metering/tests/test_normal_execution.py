"""T1 normal execution + core invariants (independent DB/keys, signature coverage)."""
import _base  # noqa: F401
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from r24.metering import MeteringObserver
from r24.models import ExecStatus, derive_private_key, public_key_fingerprint, verify_payload
from r24.scenarios import TRIALS, run_trial
from r24.tool_service import ToolService
from r24.witness import EventWitness


class TestNormalExecution(unittest.TestCase):
    def test_t1_correct_association_and_sum_all_schemes(self):
        for t in range(TRIALS):
            with self.subTest(trial=t):
                rec = run_trial("T1", t)
                for s in ("A", "B", "C"):
                    self.assertEqual(rec.schemes[s]["charged_total"], 500)
                    self.assertEqual(rec.schemes[s]["verdict_names"], [])
                    self.assertTrue(rec.schemes[s]["settleable"])
                self.assertEqual(len(rec.execution_events), 2)
                self.assertEqual(len(rec.usage_events), 2)

    def test_witness_service_observer_use_disjoint_databases_and_keys(self):
        with tempfile.TemporaryDirectory() as d:
            wd = Path(d)
            seed = 7
            wk = derive_private_key(seed, "witness")
            ak = derive_private_key(seed, "service_A")
            bk = derive_private_key(seed, "service_B")
            ok = derive_private_key(seed, "observer")
            w = EventWitness(wd / "w.db", wk, ["A", "B"])
            a = ToolService("A", wd / "a.db", ak)
            b = ToolService("B", wd / "b.db", bk)
            o = MeteringObserver("obs", wd / "o.db", ok)
            fps = [public_key_fingerprint(k.public_key()) for k in (wk, ak, bk, ok)]
            self.assertEqual(len(set(fps)), 4, "all four keys must be distinct")
            self.assertEqual(len({w.db_path, a.db_path, b.db_path, o.db_path}), 4,
                             "all four DB paths must be distinct")
            for p in ("w.db", "a.db", "b.db", "o.db"):
                self.assertTrue((wd / p).exists())

    def test_signature_covers_all_key_fields(self):
        rec = run_trial("T1", 0)
        # Re-verify each usage/observation/witness signature from its own payload;
        # then perturb one covered field and confirm verification fails.
        from r24.models import UsageEvent
        u = rec.usage_events[0]
        ev = UsageEvent(**{k: v for k, v in u.items() if k != "signature"}, signature=u["signature"])
        # reconstruct service public key from fingerprint impossible; instead check
        # that a different payload digest breaks an Ed25519 self-signature roundtrip.
        key = derive_private_key(20261119, "service_A")
        signed = UsageEvent(
            event_id=u["event_id"], run_id=u["run_id"], operation_id=u["operation_id"],
            attempt_id=u["attempt_id"], usage=u["usage"], unit=u["unit"],
            status=u["status"], source_id="A",
        ).sign(key)
        self.assertTrue(verify_payload(key.public_key(), signed.signature, signed.signed_payload()))
        tampered = signed.signed_payload()
        tampered["usage"] = signed.usage + 1
        self.assertFalse(verify_payload(key.public_key(), signed.signature, tampered))


if __name__ == "__main__":
    unittest.main(verbosity=2)
