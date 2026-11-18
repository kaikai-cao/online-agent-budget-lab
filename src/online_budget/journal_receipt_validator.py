"""E1.9-B -- server-side Receipt v2 validation (B.4, E1.9-B2.2 R2).

This module is the independent validation layer that runs INSIDE the Journal
Service before a RESULT is appended.  It reuses the frozen E1.5 Receipt v2
structure and primitives (``execution_receipts``) and does NOT introduce any
new signature scheme, encoding, or Receipt version.

Checks (all must pass; any failure rejects the append, no Entry/Checkpoint):
  1. force ``receipt_version == 2`` -- v1 / missing / non-int is rejected here,
     BEFORE calling the generic verifier (which otherwise accepts v1 AND v2);
  2. exact v2 field set (``RECEIPT_FIELDS_V2``, includes
     ``executor_authorization_digest``);
  3. Receipt signature verifies with the public key chosen from the FIXED
     ``executor_id -> public_key`` registry supplied by the caller (never a
     client-provided key);
  4. ``executor_id`` binding: Receipt.executor_id == INTENT.executor_id;
  5. ``operation_id`` binding: Receipt.operation_id == RESULT envelope.operation_id;
  6. ``binding_digest`` binding: Receipt.binding_digest == RESULT
     envelope.binding_digest == INTENT.binding_digest;
  7. ``result_digest`` recomputed with the frozen rule
     ``digest({"domain":"agent-tool-result-v1","result": result})``.

Honest boundary (E1.9-B2 §5.4.1): the Receipt is self-signed by the Executor.
A successful verification proves ONLY that the Receipt came from the registered
Executor key, is field-consistent, and is bound to the INTENT/RESULT -- it does
NOT prove the tool actually executed or that ``result`` is real.  A holder of
the Executor key can sign a fully-consistent forged Receipt.  Journal remains a
"trusted recorder", not an execution-truth oracle.
"""

from __future__ import annotations

from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import execution_receipts as er
from .canonical import digest, is_sha256


class ReceiptValidationError(ValueError):
    """A RESULT failed Receipt validation; the service must reject the append."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _receipt_payload(receipt: Any) -> Mapping[str, Any]:
    if isinstance(receipt, er.ExecutionReceipt):
        return receipt.payload
    if isinstance(receipt, Mapping):
        payload = receipt.get("payload")
        signature = receipt.get("signature_b64")
        if not isinstance(payload, Mapping) or not isinstance(signature, str):
            raise ReceiptValidationError("RECEIPT_SHAPE", "execution_receipt must contain payload and signature_b64")
        return payload
    raise ReceiptValidationError("RECEIPT_SHAPE", "execution_receipt must be an object")


def validate_result_receipt(
    *,
    receipt: Any,
    envelope: Mapping[str, Any],
    intent_executor_id: str,
    intent_binding_digest: str,
    executor_public_key: Ed25519PublicKey,
) -> None:
    """Validate a RESULT's execution_receipt; raise on any failure.

    ``envelope`` is the frozen E1.8 four-field RESULT envelope.  ``intent_*``
    values come from the signed INTENT entry (the service resolves them from its
    authoritative Journal state, never from the client).  ``executor_public_key``
    is the key selected from the FIXED registry by the authorised executor_id.
    """
    payload = _receipt_payload(receipt)

    # (1) Force Receipt v2.  Deliberately do this BEFORE the generic verifier.
    if "receipt_version" not in payload:
        raise ReceiptValidationError("RECEIPT_VERSION_MISSING", "receipt_version is missing")
    version = payload["receipt_version"]
    if isinstance(version, bool) or not isinstance(version, int) or version != 2:
        raise ReceiptValidationError("RECEIPT_VERSION_UNSUPPORTED", f"only receipt_version==2 is accepted (got {version!r})")

    # (2) Exact v2 field set.
    if set(payload) != er.RECEIPT_FIELDS_V2:
        raise ReceiptValidationError("RECEIPT_FIELDS", "receipt v2 field set does not match frozen RECEIPT_FIELDS_V2")

    # (7) result_digest recompute with the frozen rule (do this explicitly so
    # the error is attributable to this service layer, not the generic verifier).
    result = payload.get("result")
    expected_result_digest = digest({"domain": "agent-tool-result-v1", "result": result})
    if payload.get("result_digest") != expected_result_digest:
        raise ReceiptValidationError("RESULT_DIGEST_MISMATCH", "result_digest does not match frozen recomputation")

    # envelope shape (frozen E1.8 §5.2)
    if set(envelope) != {"operation_id", "binding_digest", "result", "execution_receipt"}:
        raise ReceiptValidationError("ENVELOPE_FIELDS", "RESULT envelope must be exactly four fields")
    if not is_sha256(envelope.get("binding_digest")):
        raise ReceiptValidationError("BINDING_DIGEST_FORMAT", "RESULT envelope binding_digest is not sha256")

    # (4) executor_id == INTENT executor_id
    if payload.get("executor_id") != intent_executor_id:
        raise ReceiptValidationError(
            "EXECUTOR_ID_MISMATCH", "Receipt executor_id != INTENT executor_id"
        )

    # (5) operation_id == RESULT envelope operation_id
    if payload.get("operation_id") != envelope.get("operation_id"):
        raise ReceiptValidationError(
            "OPERATION_ID_MISMATCH", "Receipt operation_id != RESULT envelope operation_id"
        )

    # (6) binding_digest: Receipt == envelope == INTENT
    if payload.get("binding_digest") != envelope.get("binding_digest"):
        raise ReceiptValidationError(
            "BINDING_DIGEST_MISMATCH", "Receipt binding_digest != RESULT envelope binding_digest"
        )
    if envelope.get("binding_digest") != intent_binding_digest:
        raise ReceiptValidationError(
            "INTENT_BINDING_MISMATCH", "RESULT envelope binding_digest != INTENT binding_digest"
        )

    # (3) signature with the registry-selected key.  Reuse the frozen verifier
    # with an expected-map so the identity/field bindings are ALSO enforced by
    # the primitive itself (defence in depth); the explicit checks above remain
    # the authoritative, attributable error source.
    try:
        ok = er.verify_execution_receipt(
            receipt,
            executor_public_key,
            expected={
                "executor_id": intent_executor_id,
                "operation_id": envelope["operation_id"],
                "binding_digest": envelope["binding_digest"],
            },
        )
    except Exception as exc:  # noqa: BLE001 - verifier raises ValueError on bad sig
        raise ReceiptValidationError("RECEIPT_SIGNATURE", "Receipt signature verification raised an error") from exc
    if not ok:
        raise ReceiptValidationError("RECEIPT_SIGNATURE", "Receipt signature verification failed")


__all__ = ["ReceiptValidationError", "validate_result_receipt"]
