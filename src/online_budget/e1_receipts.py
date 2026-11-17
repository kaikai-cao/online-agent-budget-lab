"""E1.5 independent verifier for the D11 ``E1TransitionReceipt``.

This module is the Python-side mirror of the frozen Rust rules in
``experiments/d11_3_c_coordinator/src/e1.rs`` (``E1TransitionReceipt``). It
re-derives the receipt digest and verifies the Coordinator Ed25519 signature
from a *trusted* public-key map supplied by runtime configuration -- it never
reads the local SQLite database and never trusts a caller-supplied key as the
root of trust.

Frozen rules (must stay byte-compatible with Rust):

* ``D_T = canonical_digest("d11-e1-transition-receipt-v1", unsigned_payload)``
  where ``unsigned_payload`` holds the nine business fields only (everything
  except ``transition_digest`` and ``coordinator_signature``), so there is no
  circular dependency.
* signature message = ``{"domain": "d11-e1-transition-receipt-sign-v1",
  "transition_digest": D_T}`` canonical bytes; Ed25519 over those bytes,
  standard Base64 (64-byte signature).
* ``budget_id`` / ``period_id`` / ``new_commitment`` / ``nullifier`` are
  canonical Pallas Fp hex; ``binding_digest`` / ``metering_quote_digest`` /
  ``transition_digest`` are ``sha256:`` digests; ``state_version`` is a u64.

This verifier is one gate of the E1.5 final execution boundary. Passing it does
NOT by itself authorize dispatch: the Executor still verifies the D10 grant /
authorization / budget receipt and the Metering Attestation.
"""

from __future__ import annotations

import base64
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import e1_encoding as enc
from .canonical import verify_signature

RECEIPT_DOMAIN = "d11-e1-transition-receipt-v1"
RECEIPT_SIGN_DOMAIN = "d11-e1-transition-receipt-sign-v1"

# The nine fields committed by D_T (Rust ``unsigned_payload``), and the full
# eleven-field set (Rust ``RECEIPT_FULL_FIELDS``). Order is irrelevant to the
# canonical serializer, which sorts keys, but is kept aligned with Rust.
_UNSIGNED_FIELDS = (
    "operation_id",
    "binding_digest",
    "metering_quote_digest",
    "budget_id",
    "period_id",
    "state_version",
    "new_commitment",
    "nullifier",
    "coordinator_key_id",
)
_RECEIPT_FIELDS = frozenset(_UNSIGNED_FIELDS) | {
    "transition_digest",
    "coordinator_signature",
}


class E1ExecutionDenied(ValueError):
    """The D11 Transition Receipt failed independent verification.

    Raised for any structural, encoding, digest, signature or binding failure.
    No ambiguous success value is ever returned.
    """


def _require_string(receipt: Mapping[str, Any], name: str) -> str:
    value = receipt.get(name)
    if not isinstance(value, str) or not value:
        raise E1ExecutionDenied(f"D11 receipt {name} must be a non-empty string")
    return value


def _decode_signature(value: str) -> bytes:
    """Strict standard Base64 of a 64-byte Ed25519 signature (Rust-compatible)."""
    if not isinstance(value, str) or not value:
        raise E1ExecutionDenied("D11 receipt coordinator_signature must be a non-empty string")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:  # binascii.Error / ValueError
        raise E1ExecutionDenied("D11 receipt signature is not valid standard Base64") from exc
    if len(raw) != 64:
        raise E1ExecutionDenied("D11 receipt signature must be 64 bytes")
    # Canonical round-trip: reject non-canonical padding / alphabets.
    if base64.b64encode(raw).decode("ascii") != value:
        raise E1ExecutionDenied("D11 receipt signature is not canonical Base64")
    return raw


def verify_e1_transition_receipt(
    receipt: Mapping[str, Any],
    *,
    trusted_coordinator_public_keys: Mapping[str, Ed25519PublicKey],
    expected_operation_id: str,
    expected_binding_digest: str,
    expected_metering_quote_digest: str,
    expected_budget_id: str,
    expected_period_id: str,
) -> dict[str, Any]:
    """Independently verify a D11 ``E1TransitionReceipt``.

    Args:
        receipt: the untrusted receipt object (typically from PendingExecution).
        trusted_coordinator_public_keys: ``coordinator_key_id -> public key``
            from trusted runtime configuration. This is the ONLY trust root.
        expected_*: trusted values from the D10 binding / Metering Attestation /
            budget scope that the receipt must match.

    Returns:
        A normalized copy of the verified receipt on success.

    Raises:
        E1ExecutionDenied: on any failure. Nothing is dispatched by this call.
    """
    if not isinstance(receipt, Mapping):
        raise E1ExecutionDenied("D11 receipt must be an object")
    # 1. Reject missing and extra fields (Rust `validate_field_set`).
    if set(receipt) != _RECEIPT_FIELDS:
        raise E1ExecutionDenied("D11 receipt field set does not match the signed schema")

    operation_id = _require_string(receipt, "operation_id")
    binding_digest = _require_string(receipt, "binding_digest")
    quote_digest = _require_string(receipt, "metering_quote_digest")
    budget_id = _require_string(receipt, "budget_id")
    period_id = _require_string(receipt, "period_id")
    new_commitment = _require_string(receipt, "new_commitment")
    nullifier = _require_string(receipt, "nullifier")
    coordinator_key_id = _require_string(receipt, "coordinator_key_id")
    transition_digest = _require_string(receipt, "transition_digest")

    # 2. state_version: positive u64, reject bool / float / negatives.
    state_version = receipt.get("state_version")
    if isinstance(state_version, bool) or not isinstance(state_version, int):
        raise E1ExecutionDenied("D11 receipt state_version must be an integer")
    if not (1 <= state_version <= enc.UINT64_MAX):
        raise E1ExecutionDenied("D11 receipt state_version must be a positive u64")

    # 3. Digest formats.
    for name, value in (
        ("binding_digest", binding_digest),
        ("metering_quote_digest", quote_digest),
        ("transition_digest", transition_digest),
    ):
        if not enc.is_sha256(value):
            raise E1ExecutionDenied(f"D11 receipt {name} is not a sha256 digest")

    # 4. Canonical Pallas Fp encodings (little-endian 64-char lowercase hex).
    for name, value in (
        ("budget_id", budget_id),
        ("period_id", period_id),
        ("new_commitment", new_commitment),
        ("nullifier", nullifier),
    ):
        try:
            enc.fp_from_hex(value)
        except enc.E1EncodingError as exc:
            raise E1ExecutionDenied(f"D11 receipt {name} is not canonical Pallas Fp hex") from exc

    # 5. Trust root: look up the key by id in the trusted map. A caller-supplied
    #    key is never accepted as the root of trust.
    if not isinstance(trusted_coordinator_public_keys, Mapping):
        raise E1ExecutionDenied("trusted coordinator public-key map is not a mapping")
    vk = trusted_coordinator_public_keys.get(coordinator_key_id)
    if not isinstance(vk, Ed25519PublicKey):
        raise E1ExecutionDenied("D11 receipt coordinator_key_id is not registered as trusted")

    # 6. Recompute D_T from the nine unsigned fields (no circular dependency).
    unsigned_payload = {name: receipt[name] for name in _UNSIGNED_FIELDS}
    computed_digest = enc.canonical_digest(RECEIPT_DOMAIN, unsigned_payload)
    if computed_digest != transition_digest:
        raise E1ExecutionDenied("D11 receipt transition_digest mismatch")

    # 7. Verify the Coordinator Ed25519 signature over the frozen sign message.
    _decode_signature(receipt.get("coordinator_signature"))
    sign_message = {
        "domain": RECEIPT_SIGN_DOMAIN,
        "transition_digest": computed_digest,
    }
    try:
        verify_signature(vk, receipt["coordinator_signature"], sign_message)
    except ValueError as exc:
        raise E1ExecutionDenied("D11 receipt Coordinator signature is invalid") from exc

    # 8. Cross-check the trusted expected fields.
    for name, expected in (
        ("operation_id", expected_operation_id),
        ("binding_digest", expected_binding_digest),
        ("metering_quote_digest", expected_metering_quote_digest),
        ("budget_id", expected_budget_id),
        ("period_id", expected_period_id),
    ):
        if receipt[name] != expected:
            raise E1ExecutionDenied(f"D11 receipt {name} does not match the expected value")

    return dict(receipt)


__all__ = [
    "RECEIPT_DOMAIN",
    "RECEIPT_SIGN_DOMAIN",
    "E1ExecutionDenied",
    "verify_e1_transition_receipt",
]
