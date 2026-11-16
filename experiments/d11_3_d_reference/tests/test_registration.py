"""D01–D04: issuer registration and field-encoding boundaries."""

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from experiments.d11_3_d_reference.coordinator import (
    Coordinator,
    DuplicateRegistration,
    InvalidRegistration,
)
from experiments.d11_3_d_reference.model import (
    FIELD_BYTES,
    PALLAS_FP_MODULUS,
    REGISTRATION_DOMAIN,
    FieldEncodingError,
    fp_from_bytes,
    is_field_element,
    is_valid_uint32,
)
from experiments.d11_3_d_reference.proof_verifier import TestProofVerifier
from experiments.d11_3_d_reference.registration import (
    RegistrationAuthorization,
    RegistrationFields,
    RegistrationError,
    sign_registration,
)


def issuer():
    private = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
    return private, private.public_key()


def make_fields(c0: int = 1001) -> RegistrationFields:
    return RegistrationFields(
        budget_id=101,
        period_id=7,
        quota=100,
        policy=1,
        initial_commitment=c0,
    )


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.private, self.public = issuer()
        self.verifier = TestProofVerifier()
        self.coordinator = Coordinator(self.public, self.verifier)

    def test_d01_legitimate_registration_accepted(self):
        auth = sign_registration(make_fields(), self.private)
        auth.verify(self.public)
        self.coordinator.register(auth)

        state = self.coordinator.get_state(101, 7)
        self.assertIsNotNone(state)
        self.assertEqual(state.quota, 100)
        self.assertEqual(state.policy, 1)
        self.assertEqual(state.current_commitment, 1001)
        self.assertEqual(state.version, 0)
        self.assertEqual(state.authorization, auth.encode())
        self.assertEqual(RegistrationAuthorization.decode(auth.encode()), auth)

    def test_d02_tampered_signature_rejected(self):
        auth = sign_registration(make_fields(), self.private)
        tampered = RegistrationAuthorization(
            fields=auth.fields,
            issuer_signature=bytes([auth.issuer_signature[0] ^ 1])
            + auth.issuer_signature[1:],
        )
        with self.assertRaises(RegistrationError):
            tampered.verify(self.public)
        with self.assertRaises(InvalidRegistration):
            self.coordinator.register(tampered)
        self.assertIsNone(self.coordinator.get_state(101, 7))

    def test_d03_fields_do_not_match_signature(self):
        auth = sign_registration(make_fields(), self.private)
        changed = RegistrationAuthorization(
            fields=RegistrationFields(
                budget_id=auth.fields.budget_id,
                period_id=auth.fields.period_id,
                quota=200,
                policy=auth.fields.policy,
                initial_commitment=auth.fields.initial_commitment,
            ),
            issuer_signature=auth.issuer_signature,
        )
        with self.assertRaises(InvalidRegistration):
            self.coordinator.register(changed)

    def test_d04_duplicate_and_conflicting_registration_rejected(self):
        auth = sign_registration(make_fields(), self.private)
        self.coordinator.register(auth)
        with self.assertRaises(DuplicateRegistration):
            self.coordinator.register(auth)

        conflicting = sign_registration(make_fields(c0=2001), self.private)
        with self.assertRaises(DuplicateRegistration):
            self.coordinator.register(conflicting)
        self.assertEqual(self.coordinator.get_state(101, 7).current_commitment, 1001)

    def test_encoding_mirrors_rust_c_field_order_and_endianness(self):
        expected = (
            REGISTRATION_DOMAIN
            + (101).to_bytes(FIELD_BYTES, "little")
            + (7).to_bytes(FIELD_BYTES, "little")
            + (100).to_bytes(FIELD_BYTES, "little")
            + (1).to_bytes(FIELD_BYTES, "little")
            + (1001).to_bytes(FIELD_BYTES, "little")
        )
        self.assertEqual(make_fields().encode(), expected)
        self.assertTrue(expected.startswith(b"D11.3-C-REGISTRATION-v1"))

    def test_field_and_uint32_boundaries(self):
        self.assertFalse(is_field_element(True))
        self.assertFalse(is_field_element(-1))
        self.assertFalse(is_field_element(PALLAS_FP_MODULUS))
        self.assertTrue(is_field_element(PALLAS_FP_MODULUS - 1))
        self.assertFalse(is_valid_uint32(True))
        self.assertFalse(is_valid_uint32(-1))
        self.assertFalse(is_valid_uint32(2**32))

        with self.assertRaises(FieldEncodingError):
            fp_from_bytes(PALLAS_FP_MODULUS.to_bytes(FIELD_BYTES, "little"))
        with self.assertRaises(FieldEncodingError):
            fp_from_bytes(b"\x01\x02")

        for bad in (True, -1, PALLAS_FP_MODULUS):
            with self.assertRaises(RegistrationError):
                RegistrationFields(
                    budget_id=bad,
                    period_id=7,
                    quota=100,
                    policy=1,
                    initial_commitment=1001,
                )
        for bad_quota in (True, 0, -1, 2**32):
            with self.assertRaises(RegistrationError):
                RegistrationFields(
                    budget_id=101,
                    period_id=7,
                    quota=bad_quota,
                    policy=1,
                    initial_commitment=1001,
                )


if __name__ == "__main__":
    unittest.main()
