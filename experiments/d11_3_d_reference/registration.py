"""Issuer registration authorization, encoded exactly like Rust D11.3-C.

Signed message = REGISTRATION_DOMAIN || budget_id || period_id || Q || P || C_0,
where each field is the canonical 32-byte little-endian Pallas Fp encoding.
The stored/encoded authorization appends the 64-byte Ed25519 signature.

Ed25519 comes from the project's existing `cryptography` dependency; no second
signature scheme is introduced. This is only signature verification: as in
D11.3-A §4.1, it does not prove knowledge of the C_0 opening.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .model import (
    FIELD_BYTES,
    MAX_UINT32,
    REGISTRATION_DOMAIN,
    FieldEncodingError,
    fp_from_bytes,
    fp_to_bytes,
    is_field_element,
    is_valid_uint32,
)

SIGNATURE_LEN = 64
FIELD_COUNT = 5
ENCODED_LEN = len(REGISTRATION_DOMAIN) + FIELD_COUNT * FIELD_BYTES + SIGNATURE_LEN


class RegistrationError(ValueError):
    """Invalid registration authorization or field encoding."""


@dataclass(frozen=True)
class RegistrationFields:
    budget_id: int
    period_id: int
    quota: int
    policy: int
    initial_commitment: int

    def __post_init__(self) -> None:
        for name in ("budget_id", "period_id", "policy", "initial_commitment"):
            if not is_field_element(getattr(self, name)):
                raise RegistrationError(f"{name} is not a canonical Pallas field element")
        if not is_valid_uint32(self.quota) or self.quota < 1 or self.quota > MAX_UINT32:
            raise RegistrationError("quota must satisfy 1 <= Q <= 2^32-1")

    def encode(self) -> bytes:
        return REGISTRATION_DOMAIN + b"".join(
            fp_to_bytes(value)
            for value in (
                self.budget_id,
                self.period_id,
                self.quota,
                self.policy,
                self.initial_commitment,
            )
        )

    @classmethod
    def from_message(cls, message: bytes) -> "RegistrationFields":
        prefix_len = len(REGISTRATION_DOMAIN)
        if len(message) != prefix_len + FIELD_COUNT * FIELD_BYTES:
            raise RegistrationError("unexpected signed-message length")
        if message[:prefix_len] != REGISTRATION_DOMAIN:
            raise RegistrationError("unexpected domain separator")
        values = []
        for index in range(FIELD_COUNT):
            start = prefix_len + index * FIELD_BYTES
            try:
                values.append(fp_from_bytes(message[start : start + FIELD_BYTES]))
            except FieldEncodingError as exc:
                raise RegistrationError(str(exc)) from exc
        return cls(*values)


@dataclass(frozen=True)
class RegistrationAuthorization:
    fields: RegistrationFields
    issuer_signature: bytes

    def encode(self) -> bytes:
        return self.fields.encode() + self.issuer_signature

    @classmethod
    def decode(cls, data: bytes) -> "RegistrationAuthorization":
        if not isinstance(data, (bytes, bytearray)) or len(data) != ENCODED_LEN:
            raise RegistrationError(
                f"encoded authorization must be exactly {ENCODED_LEN} bytes"
            )
        split = ENCODED_LEN - SIGNATURE_LEN
        return cls(
            fields=RegistrationFields.from_message(bytes(data[:split])),
            issuer_signature=bytes(data[split:]),
        )

    def verify(self, issuer: Ed25519PublicKey) -> None:
        """Raise RegistrationError unless the issuer signature is valid."""
        if len(self.issuer_signature) != SIGNATURE_LEN:
            raise RegistrationError("Ed25519 signature must be 64 bytes")
        try:
            issuer.verify(self.issuer_signature, self.fields.encode())
        except InvalidSignature as exc:
            raise RegistrationError("issuer registration signature is invalid") from exc
        except (TypeError, ValueError) as exc:
            raise RegistrationError(f"invalid issuer key/signature input: {exc}") from exc


def sign_registration(
    fields: RegistrationFields, issuer: Ed25519PrivateKey
) -> RegistrationAuthorization:
    """Issuer side helper; the Coordinator only verifies."""
    return RegistrationAuthorization(
        fields=fields,
        issuer_signature=issuer.sign(fields.encode()),
    )
