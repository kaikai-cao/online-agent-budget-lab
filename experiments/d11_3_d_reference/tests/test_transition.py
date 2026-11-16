"""D05–D10 and D13–D14: real transition flow, tampering and isolation."""

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.d11_3_d_reference.coordinator import (
    Coordinator,
    PolicyMismatch,
    ProofVerificationFailed,
    QuotaMismatch,
    StaleCommitment,
    UnregisteredInstance,
)
from experiments.d11_3_d_reference.model import (
    PALLAS_FP_MODULUS,
    StateWitness,
    Transition,
)
from experiments.d11_3_d_reference.proof_verifier import ProofRejected, TestProofVerifier
from experiments.d11_3_d_reference.registration import RegistrationFields, sign_registration


def witness(budget_id: int = 101, period_id: int = 7) -> StateWitness:
    return StateWitness(
        budget_id=budget_id,
        period_id=period_id,
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


def transition(w: StateWitness, seed: int = 0) -> Transition:
    base = 1001 + seed * 3
    return Transition(w, c_old=base, c_new=base + 1, nullifier=base + 2)


def setup(budget_id=101, period_id=7, seed=0):
    private = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
    verifier = TestProofVerifier()
    coordinator = Coordinator(private.public_key(), verifier)
    w = witness(budget_id, period_id)
    tr = transition(w, seed)
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
    proof = verifier.issue(tr)  # prover side; the Coordinator never issues proofs
    return coordinator, tr, proof, private


class TransitionTests(unittest.TestCase):
    def test_d05_unregistered_instance_rejected(self):
        private = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
        verifier = TestProofVerifier()
        coordinator = Coordinator(private.public_key(), verifier)
        tr = transition(witness())
        proof = verifier.issue(tr)
        with self.assertRaises(UnregisteredInstance):
            coordinator.submit_transition(proof, tr.public_inputs())

    def test_d06_valid_transition_accepted(self):
        coordinator, tr, proof, _ = setup()
        receipt = coordinator.submit_transition(proof, tr.public_inputs())
        self.assertEqual(receipt.version, 1)
        self.assertEqual(receipt.new_commitment, tr.c_new)
        self.assertEqual(receipt.nullifier, tr.nullifier)

        state = coordinator.get_state(101, 7)
        self.assertEqual(state.current_commitment, tr.c_new)
        self.assertEqual(state.version, 1)
        self.assertIn(tr.nullifier, state.used_nullifiers)

    def test_d07_invalid_proof_rejected(self):
        coordinator, tr, _, _ = setup()
        with self.assertRaises(ProofVerificationFailed):
            coordinator.submit_transition(b"garbage-proof", tr.public_inputs())

    def test_d08_tampered_public_inputs_rejected(self):
        coordinator, tr, proof, _ = setup()
        for row in (4, 5, 6):  # C_old, C_new, N
            with self.subTest(row=row):
                tampered = list(tr.public_inputs())
                tampered[row] += 1
                # A tampered C_old is caught by the explicit stale-state check
                # before proof verification; C_new/N tampering reaches the
                # verifier, which must reject the mismatched public instance.
                expected = StaleCommitment if row == 4 else ProofVerificationFailed
                with self.assertRaises(expected):
                    coordinator.submit_transition(proof, tampered)
        self.assertEqual(coordinator.get_state(101, 7).version, 0)

    def test_test_verifier_binds_all_eight_public_rows(self):
        # Direct check of the test verifier boundary: no `verified` flag, and
        # every single public row is covered by the binding.
        tr = transition(witness())
        verifier = TestProofVerifier()
        proof = verifier.issue(tr)
        original = tr.public_inputs()
        verifier.verify(proof, original)
        for row in range(8):
            with self.subTest(row=row):
                tampered = list(original)
                tampered[row] += 1
                with self.assertRaises(ProofRejected):
                    verifier.verify(proof, tampered)

    def test_d09_quota_mismatch_rejected(self):
        coordinator, tr, proof, _ = setup()
        tampered = list(tr.public_inputs())
        tampered[2] = 99
        with self.assertRaises(QuotaMismatch):
            coordinator.submit_transition(proof, tampered)

    def test_d10_policy_mismatch_rejected(self):
        coordinator, tr, proof, _ = setup()
        tampered = list(tr.public_inputs())
        tampered[7] = 2
        with self.assertRaises(PolicyMismatch):
            coordinator.submit_transition(proof, tampered)

    def test_d13_budget_instances_are_isolated(self):
        private = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
        verifier = TestProofVerifier()
        coordinator = Coordinator(private.public_key(), verifier)
        first_w, second_w = witness(101, 7), witness(102, 7)
        first_tr, second_tr = transition(first_w, 0), transition(second_w, 1)
        for w, tr in ((first_w, first_tr), (second_w, second_tr)):
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
        proof_a = verifier.issue(first_tr)
        proof_b = verifier.issue(second_tr)
        coordinator.submit_transition(proof_a, first_tr.public_inputs())
        coordinator.submit_transition(proof_b, second_tr.public_inputs())
        with self.assertRaises(Exception):
            coordinator.submit_transition(proof_a, second_tr.public_inputs())

        state_a = coordinator.get_state(101, 7)
        state_b = coordinator.get_state(102, 7)
        self.assertEqual(state_a.current_commitment, first_tr.c_new)
        self.assertEqual(state_b.current_commitment, second_tr.c_new)
        self.assertNotEqual(state_a.current_commitment, state_b.current_commitment)
        self.assertEqual(len(state_a.used_nullifiers), 1)
        self.assertEqual(len(state_b.used_nullifiers), 1)

    def test_d14_periods_are_isolated(self):
        private = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
        verifier = TestProofVerifier()
        coordinator = Coordinator(private.public_key(), verifier)
        first_w, second_w = witness(101, 7), witness(101, 8)
        first_tr, second_tr = transition(first_w, 0), transition(second_w, 1)
        for w, tr in ((first_w, first_tr), (second_w, second_tr)):
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
        proof_a = verifier.issue(first_tr)
        proof_b = verifier.issue(second_tr)
        coordinator.submit_transition(proof_a, first_tr.public_inputs())
        coordinator.submit_transition(proof_b, second_tr.public_inputs())
        with self.assertRaises(Exception):
            coordinator.submit_transition(proof_a, second_tr.public_inputs())

        self.assertEqual(coordinator.get_state(101, 7).current_commitment, first_tr.c_new)
        self.assertEqual(coordinator.get_state(101, 8).current_commitment, second_tr.c_new)

    def test_witness_and_relation_boundaries(self):
        base = dict(
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
        for key, bad in (
            ("quota", True),
            ("quota", -1),
            ("quota", 2**32),
            ("cost", 2**32),
            ("u_old", -1),
            ("nf_secret", PALLAS_FP_MODULUS),
            ("budget_id", True),
        ):
            with self.subTest(key=key, bad=bad):
                values = dict(base)
                values[key] = bad
                with self.assertRaises(ValueError):
                    StateWitness(**values)

        broken = StateWitness(**{**base, "u_new": 21})  # slack still 80: 21+80 != 100
        with self.assertRaises(ValueError):
            broken.check_relations()
        broken2 = StateWitness(**{**base, "u_old": 1, "u_new": 21})
        with self.assertRaises(ValueError):
            broken2.check_relations()  # 6a ok (1+20=21) but 6b broken (21+80 != 100)


if __name__ == "__main__":
    unittest.main()
