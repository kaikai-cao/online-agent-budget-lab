"""Records, canonical signing and helpers for R2.4 Phase 2.

Design discipline
-----------------
* Every observable artifact is a signed record with ``signed_payload()`` so the
  signature covers all fields the verifier relies on.
* Ground-truth records are a SEPARATE type (``GroundTruthEvent``) that lives in
  the experiment controller only. It is NEVER passed into any verifier view.
  This is enforced structurally: verifier functions accept only observable
  record types; a helper ``assert_no_ground_truth`` is used by tests.
* Keys are deterministic per (seed, domain), disjoint, never written to disk.
* This phase counts TOOL CALL EVENTS only (no token/CPU/GPU metering).
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
    Ed25519PrivateKey, Ed25519PublicKey,
)


class FinalResult(str, Enum):
    """Verifier's per-call outcome (four schemes share this taxonomy)."""
    COVERED = "COVERED"        # observable evidence supports full coverage
    MISSING_EVIDENCE = "MISSING_EVIDENCE"  # expected/forwarded call lacks evidence
    UNCERTAIN = "UNCERTAIN"    # observable evidence inconsistent/incomplete
    BYPASS_DETECTED = "BYPASS_DETECTED"  # entrance saw an unauthenticated request
    NO_EVIDENCE = "NO_EVIDENCE"          # nothing observable (scheme is blind)
    DUPLICATE_IGNORED = "DUPLICATE_IGNORED"  # repeat transmission, one logical attempt


# ---------------------------------------------------------------------------
# canonical encoding + Ed25519
# ---------------------------------------------------------------------------

def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def derive_key(seed: int, domain: str) -> Ed25519PrivateKey:
    material = hashlib.sha256(f"r24p2|{seed}|{domain}".encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(material)


def fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sign(key: Ed25519PrivateKey, payload: dict[str, Any]) -> str:
    return _b64e(key.sign(canonical_bytes(payload)))


def verify(key: Ed25519PublicKey, signature: str, payload: dict[str, Any]) -> bool:
    try:
        key.verify(_b64d(signature), canonical_bytes(payload))
        return True
    except (ValueError, InvalidSignature):
        return False


def _signed_dataclass(cls):
    """Add sign()/is_valid()/to_dict() to a frozen-by-convention record."""
    def _do_sign(self, key: Ed25519PrivateKey):
        # NB: name must differ from module-level sign() to avoid shadowing.
        object.__setattr__(self, "signature", sign(key, self.signed_payload()))
        return self

    def _do_is_valid(self, key: Ed25519PublicKey) -> bool:
        return bool(self.signature) and verify(key, self.signature, self.signed_payload())

    def _do_to_dict(self) -> dict[str, Any]:
        return asdict(self)

    cls.sign = _do_sign
    cls.is_valid = _do_is_valid
    cls.to_dict = _do_to_dict
    return cls


# ---------------------------------------------------------------------------
# Observable records (these may enter a verifier view)
# ---------------------------------------------------------------------------

@_signed_dataclass
@dataclass
class ForwardReceipt:
    """Gateway-issued, signed proof that it FORWARDED a call to a service.

    Existence proves only that the call traversed the gateway — NOT that the
    service executed it (this is the T3 crux).
    """
    run_id: str
    logical_call_id: str
    attempt_id: str
    service_id: str
    gateway_id: str
    signature: str = ""

    def signed_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "logical_call_id": self.logical_call_id,
            "attempt_id": self.attempt_id, "service_id": self.service_id,
            "gateway_id": self.gateway_id,
        }


@_signed_dataclass
@dataclass
class ServiceSubmission:
    """Service-signed self-report that it accepted/executed a call."""
    run_id: str
    logical_call_id: str
    attempt_id: str
    service_id: str
    service_executed_claim: bool
    signature: str = ""

    def signed_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "logical_call_id": self.logical_call_id,
            "attempt_id": self.attempt_id, "service_id": self.service_id,
            "service_executed_claim": self.service_executed_claim,
        }


@_signed_dataclass
@dataclass
class IngressObservation:
    """Independent ingress observer's signed record of a request reaching the
    service entrance. Separate DB + key; service has no handle to it."""
    run_id: str
    logical_call_id: str
    attempt_id: str
    service_id: str
    observer_id: str
    gateway_authenticated: bool   # did the request carry a valid gateway proof?
    signature: str = ""

    def signed_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "logical_call_id": self.logical_call_id,
            "attempt_id": self.attempt_id, "service_id": self.service_id,
            "observer_id": self.observer_id,
            "gateway_authenticated": self.gateway_authenticated,
        }


@_signed_dataclass
@dataclass
class WitnessExpectation:
    """Witness-registered expected call intent (independent key + DB)."""
    run_id: str
    logical_call_id: str
    attempt_id: str
    service_id: str
    signature: str = ""

    def signed_payload(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id, "logical_call_id": self.logical_call_id,
            "attempt_id": self.attempt_id, "service_id": self.service_id,
        }


# ---------------------------------------------------------------------------
# Ground-truth record — CONTROLLER ONLY, never a verifier input
# ---------------------------------------------------------------------------

@dataclass
class GroundTruthEvent:
    """Authoritative outcome recorded by the INDEPENDENT experiment controller.

    ``service_executed`` is ground truth. It must never be exposed to the code
    under test. Only the controller uses it, when scoring the four metrics.
    """
    run_id: str
    logical_call_id: str
    attempt_id: str
    service_id: str
    gateway_received: bool
    gateway_forwarded: bool
    service_accepted: bool
    service_executed: bool
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CallOutcome:
    """What the controller observes from one simulated call attempt."""
    forward_receipt: ForwardReceipt | None
    submission: ServiceSubmission | None
    ingress_observation: IngressObservation | None
    witness_expectation: WitnessExpectation | None
    ground_truth: GroundTruthEvent
    # whether the Observer dropped its record (T5) — controller-side fact
    observer_record_dropped: bool = False


@dataclass
class Verdict:
    """A scheme's per-call decision over OBSERVABLE evidence only."""
    scheme: str
    logical_call_id: str
    attempt_id: str
    result: FinalResult
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["result"] = self.result.value if isinstance(self.result, FinalResult) else self.result
        return d


def assert_no_ground_truth(obj: Any) -> None:
    """Defensive check used by tests: a verifier view must not carry GT fields."""
    forbidden = {"ground_truth", "service_executed", "gateway_received",
                 "gateway_forwarded", "service_accepted"}
    if isinstance(obj, dict):
        hit = forbidden & set(obj.keys())
        if hit:
            raise AssertionError(f"ground-truth field leaked into verifier view: {hit}")
    if hasattr(obj, "__dataclass_fields__"):
        hit = forbidden & set(obj.__dataclass_fields__.keys())
        if hit:
            raise AssertionError(f"ground-truth field leaked into verifier object: {hit}")
