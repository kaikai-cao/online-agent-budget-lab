"""D15: two real OS threads competing for the same C_old."""

import threading
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.d11_3_d_reference.coordinator import Coordinator
from experiments.d11_3_d_reference.model import StateWitness, Transition
from experiments.d11_3_d_reference.proof_verifier import TestProofVerifier
from experiments.d11_3_d_reference.registration import RegistrationFields, sign_registration


def setup():
    private = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
    verifier = TestProofVerifier()
    coordinator = Coordinator(private.public_key(), verifier)
    w = StateWitness(
        budget_id=101,
        period_id=7,
        quota=100,
        cost=20,
        u_old=0,
        u_new=20,
        slack=80,
        r_old=11,
        r_new=13,
        nf_secret=17,
        policy=1,
    )
    tr = Transition(w, c_old=1001, c_new=1002, nullifier=1003)
    coordinator.register(
        sign_registration(
            RegistrationFields(
                budget_id=w.budget_id,
                period_id=w.period_id,
                quota=w.quota,
                policy=w.policy,
                initial_commitment=tr.c_old,
            ),
            private,
        )
    )
    return coordinator, verifier.issue(tr), tr


class ConcurrencyTests(unittest.TestCase):
    def test_d15_two_threads_competing_for_same_c_old(self):
        coordinator, proof, tr = setup()
        instance = tr.public_inputs()
        barrier = threading.Barrier(2)
        results = []

        def worker():
            barrier.wait()
            try:
                coordinator.submit_transition(proof, instance)
                results.append("accepted")
            except Exception:
                results.append("rejected")

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(results.count("accepted"), 1)
        self.assertEqual(results.count("rejected"), 1)
        state = coordinator.get_state(101, 7)
        self.assertEqual(state.version, 1)
        self.assertEqual(state.current_commitment, tr.c_new)
        self.assertEqual(state.used_nullifiers, {tr.nullifier})


if __name__ == "__main__":
    unittest.main()
