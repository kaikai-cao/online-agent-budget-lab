"""Core records, enums, canonical encoding and Ed25519 helpers for R2.4.

Design notes
------------
* Four core records only: ExecutionEvent, UsageEvent, MeteringObservation,
  VerificationResult. No over-engineering.
* Every signed record exposes ``signed_payload()``: the EXACT dict that is
  canonical-JSON encoded and signed. The signature therefore covers every
  field the verifier relies on; no key field is left outside the signature.
* Keys are generated in memory and derived deterministically from the fixed
  experiment seed, so results are reproducible WITHOUT storing any private key.
  Public-key fingerprints are recorded for independent audit. Three domains
  (witness / service / observer) use three disjoint private keys.
* Verdicts are intentionally fine-grained. Never collapse anomalies to a
  generic ``INVALID``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ExecStatus(str, Enum):
    REGISTERED = "REGISTERED"
    DISPATCHED = "DISPATCHED"
    MEASURED = "MEASURED"
    PARTIAL = "PARTIAL"
    UNCERTAIN = "UNCERTAIN"
    CORRECTED = "CORRECTED"
    FINALIZED = "FINALIZED"


class UsageStatus(str, Enum):
    MEASURED = "MEASURED"
    PARTIAL = "PARTIAL"
    UNCERTAIN = "UNCERTAIN"
    CORRECTED = "CORRECTED"
    FINALIZED = "FINALIZED"


class Verdict(str, Enum):
    ACCEPTED = "ACCEPTED"
    MISSING_USAGE_EVENT = "MISSING_USAGE_EVENT"
    DUPLICATE_USAGE_EVENT = "DUPLICATE_USAGE_EVENT"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    USAGE_MISMATCH = "USAGE_MISMATCH"
    INCOMPLETE_EXECUTION_STATUS = "INCOMPLETE_EXECUTION_STATUS"
    UNKNOWN_EVENT = "UNKNOWN_EVENT"
    INVALID_EVENT_LINKAGE = "INVALID_EVENT_LINKAGE"


# Flagship terminal state: an UNCERTAIN status must never settle as zero.
NON_SETTLEABLE_STATUSES = {ExecStatus.UNCERTAIN, ExecStatus.PARTIAL}


# ---------------------------------------------------------------------------
# Canonical encoding + Ed25519 helpers (self-contained; no frozen code import)
# ---------------------------------------------------------------------------


def canonical_json_bytes(value: Any) -> bytes:
    """RFC-8785-style canonicalization sufficient for this closed prototype."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"not canonical-JSON serializable: {exc}") from exc


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64v(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def derive_private_key(seed: int, domain: str) -> Ed25519PrivateKey:
    """Deterministic, disjoint key per (seed, domain). No private key on disk."""
    material = hashlib.sha256(f"r24|{seed}|{domain}".encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(material)


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sign_payload(key: Ed25519PrivateKey, payload: dict[str, Any]) -> str:
    return _b64e(key.sign(canonical_json_bytes(payload)))


def verify_payload(
    key: Ed25519PublicKey, signature: str, payload: dict[str, Any]
) -> bool:
    try:
        key.verify(_b64v(signature), canonical_json_bytes(payload))
        return True
    except (ValueError, InvalidSignature):
        return False


# ---------------------------------------------------------------------------
# Core records
# ---------------------------------------------------------------------------


@dataclass
class ExecutionEvent:
    """Witness-registered execution intent (NOT proof that execution happened)."""

    run_id: str
    service_id: str
    operation_id: str
    attempt_id: str
    event_id: str
    sequence_no: int
    request_digest: str
    registered_at: str
    status: str
    witness_signature: str = ""

    def signed_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "service_id": self.service_id,
            "operation_id": self.operation_id,
            "attempt_id": self.attempt_id,
            "event_id": self.event_id,
            "sequence_no": self.sequence_no,
            "request_digest": self.request_digest,
            "registered_at": self.registered_at,
            "status": self.status,
        }

    def sign(self, key: Ed25519PrivateKey) -> "ExecutionEvent":
        self.witness_signature = sign_payload(key, self.signed_payload())
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UsageEvent:
    """Service-signed metering claim. Signature proves origin+integrity, NOT truth."""

    event_id: str
    run_id: str
    operation_id: str
    attempt_id: str
    usage: int
    unit: str
    status: str
    source_id: str
    signature: str = ""

    def signed_payload(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "run_id": self.run_id,
            "operation_id": self.operation_id,
            "attempt_id": self.attempt_id,
            "usage": self.usage,
            "unit": self.unit,
            "status": self.status,
            "source_id": self.source_id,
        }

    def sign(self, key: Ed25519PrivateKey) -> "UsageEvent":
        self.signature = sign_payload(key, self.signed_payload())
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MeteringObservation:
    """Independent metering observation (configuration B/C only).

    A simulated trusted observation point. NOT a real TEE / cloud / third-party
    metering guarantee.
    """

    event_id: str
    observed_usage: int
    unit: str
    observer_id: str
    signature: str = ""

    def signed_payload(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "observed_usage": self.observed_usage,
            "unit": self.unit,
            "observer_id": self.observer_id,
        }

    def sign(self, key: Ed25519PrivateKey) -> "MeteringObservation":
        self.signature = sign_payload(key, self.signed_payload())
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    verdict: str
    scheme: str
    event_id: str
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Legal status transitions (documentation of the intended state machine)
# ---------------------------------------------------------------------------

LEGAL_TRANSITIONS: dict[str, set[str]] = {
    ExecStatus.REGISTERED.value: {ExecStatus.DISPATCHED.value},
    ExecStatus.DISPATCHED.value: {
        ExecStatus.MEASURED.value,
        ExecStatus.PARTIAL.value,
        ExecStatus.UNCERTAIN.value,
    },
    ExecStatus.MEASURED.value: {ExecStatus.FINALIZED.value, ExecStatus.CORRECTED.value},
    ExecStatus.PARTIAL.value: {ExecStatus.CORRECTED.value, ExecStatus.UNCERTAIN.value},
    ExecStatus.UNCERTAIN.value: {ExecStatus.CORRECTED.value},
    ExecStatus.CORRECTED.value: {ExecStatus.FINALIZED.value},
    ExecStatus.FINALIZED.value: set(),  # late events may NOT silently overwrite
}


def is_legal_transition(old: str, new: str) -> bool:
    return new in LEGAL_TRANSITIONS.get(old, set())
