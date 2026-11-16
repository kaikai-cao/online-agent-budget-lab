"""Abstract proof-verification boundary for the Python reference model.

CRITICAL BOUNDARY: this is NOT a zero-knowledge verifier and NOT a Halo2
implementation. The test verifier binds an opaque test token to the complete
eight-row public instance; changing any row makes verification fail. Real proof
generation and verification live in the Rust D11.3-B.1/C code.

There is deliberately no `verified=True` or equivalent bypass parameter:
`verify()` only accepts a proof object plus the public instance.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Protocol, Sequence

from .model import INSTANCE_ROWS, Transition, is_field_element

# Explicitly test-only marker, never to be confused with D11.3-B.0 Poseidon.
TEST_TOKEN_PREFIX = b"D11.3-D-TEST-PROOF-v1"


class ProofRejected(Exception):
    """The proof does not validate against the supplied public instance."""


@dataclass(frozen=True)
class TestProof:
    """Opaque test token produced by `TestProofVerifier.issue`."""

    token: bytes


class ProofVerifier(Protocol):
    def verify(self, proof: object, instance: Sequence[int]) -> None:
        """Raise ProofRejected when the proof does not match `instance`."""
        ...


class TestProofVerifier:
    """Test-only stand-in for the verifier interface.

    `issue()` is the prover side: it checks the two budget equations over the
    witness and records a token bound to the resulting public instance.
    `verify()` is the only path the Coordinator uses; it looks up the token in
    verifier-private state and compares ALL eight public rows.
    """

    def __init__(self) -> None:
        self._issued: dict[bytes, tuple[int, ...]] = {}

    def issue(self, transition: Transition) -> TestProof:
        if not isinstance(transition, Transition):
            raise ProofRejected("issue() requires a Transition")
        transition.witness.check_relations()
        instance = transition.public_inputs()
        if len(instance) != INSTANCE_ROWS or not all(is_field_element(v) for v in instance):
            raise ProofRejected("public instance has invalid field elements")
        token = TEST_TOKEN_PREFIX + secrets.token_bytes(32)
        self._issued[token] = instance
        return TestProof(token=token)

    def verify(self, proof: object, instance: Sequence[int]) -> None:
        if not isinstance(proof, TestProof):
            raise ProofRejected("not a test proof")
        expected = self._issued.get(proof.token)
        if expected is None:
            raise ProofRejected("unissued or unknown test proof")
        if tuple(instance) != expected:
            raise ProofRejected("public input does not match the proof")
