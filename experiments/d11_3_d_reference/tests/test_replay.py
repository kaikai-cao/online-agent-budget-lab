"""D11, D12 and D16: replay, stale state and update-failure rollback."""

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.d11_3_d_reference.coordinator import (
    Coordinator,
    NullifierReused,
    StaleCommitment,
)
from experiments.d11_3_d_reference.model import StateWitness, Transition
from experiments.d11_3_d_reference.proof_verifier import TestProofVerifier
from experiments.d11_3_d_reference.registration import RegistrationFields, sign_registration


def setup(fault_hook=None):
    private = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
    verifier = TestProofVerifier()
    coordinator = Coordinator(private.public_key(), verifier, fault_hook=fault_hook)
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


class ReplayTests(unittest.TestCase):
    def test_d11_reused_nullifier_rejected_without_state_change(self):
        coordinator, proof, tr = setup()
        # Seed N while C_old is still current, isolating the nullifier check.
        coordinator.seed_used_nullifier(101, 7, tr.nullifier)
        with self.assertRaises(NullifierReused):
            coordinator.submit_transition(proof, tr.public_inputs())
        state = coordinator.get_state(101, 7)
        self.assertEqual(state.version, 0)
        self.assertEqual(state.current_commitment, tr.c_old)

    def test_d12_stale_c_old_rejected(self):
        coordinator, proof, tr = setup()
        coordinator.submit_transition(proof, tr.public_inputs())
        with self.assertRaises(StaleCommitment):
            coordinator.submit_transition(proof, tr.public_inputs())
        state = coordinator.get_state(101, 7)
        self.assertEqual(state.version, 1)
        self.assertEqual(state.current_commitment, tr.c_new)
        self.assertEqual(state.used_nullifiers, {tr.nullifier})

    def test_d16_failed_update_leaves_state_and_nullifier_unchanged(self):
        def injected_failure():
            raise RuntimeError("injected update failure")

        coordinator, proof, tr = setup(fault_hook=injected_failure)
        with self.assertRaises(RuntimeError):
            coordinator.submit_transition(proof, tr.public_inputs())
        state = coordinator.get_state(101, 7)
        self.assertEqual(state.version, 0)
        self.assertEqual(state.current_commitment, tr.c_old)
        self.assertEqual(state.used_nullifiers, set())


if __name__ == "__main__":
    unittest.main()
