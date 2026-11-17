"""E1.2 Metering Policy and Metering Attestation (Python, standalone).

This module lands E1.0 §4 on top of the frozen E1.1 encoding layer. It is a
standalone, trusted-Executor-side component only: it is NOT wired into the E1
Runtime, the D10 default execution path, or the D11 Rust Coordinator in this
stage. Those integrations belong to E1.3/E1.4.

Trust model (E1.0 §1.4 / §4.5):
- The Issuer signs a Metering Policy; the trusted Executor computes ``c`` from
  that signed policy and signs a Metering Attestation with its own Ed25519 key.
- ``c`` is an admission-time weighted charge fixed BEFORE execution. It is not
  a measurement of CPU/tokens/memory and must never be described as such.
- A Planner-supplied ``c`` is never accepted. Cost is internal-only, derived
  from an exact (tool_name, tool_schema_hash) lookup in a verified policy.
- The Metering Policy digest and the Pallas field element ``P`` are distinct:
  ``P`` is an Issuer-assigned identifier; the digest is a SHA-256 over canonical
  bytes. No truncation/modulo of a SHA-256 is used to manufacture ``P``.

Encoding is reused from E1.1 (canonical_digest / fp hex / uint32 checks) and
the Ed25519 conventions are reused from ``online_budget.canonical``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import e1_encoding as enc
from .canonical import (
    b64encode,
    canonical_json_bytes,
    public_key_bytes,
    verify_signature,
)
from .executor_authorization import ExecutorAuthorization
from .tool_binding import ToolCallBinding

# Frozen domain prefixes (E1.2 task §3.2 / §5.2). Distinct from every other
# D10/D11 domain so signatures cannot be replayed across protocols.
POLICY_DOMAIN = "d11-e1-metering-policy-v1"
ATTESTATION_DOMAIN = "d11-e1-metering-attestation-v1"

# Unsigned business fields only (signature is stored in the outer envelope).
POLICY_FIELDS = {"version", "issuer_id", "policy_version", "P", "entries"}
POLICY_ENTRY_FIELDS = {"tool_name", "tool_schema_hash", "cost"}
ATTESTATION_FIELDS = {
    "version",
    "executor_id",
    "operation_id",
    "binding_digest",
    "executor_authorization_digest",
    "arguments_digest",
    "canonicalization_version",
    "tool_name",
    "tool_schema_hash",
    "global_budget_id",
    "lease_id",
    "budget_id",
    "period_id",
    "Q",
    "P",
    "c",
    "metering_policy_digest",
    "issued_at",
    "expires_at",
}

# Fields of the trusted upstream cross-layer budget scope (E1.0 §3.2). They are
# supplied by the Issuer-signed binding record; E1.2 only carries them as typed
# input and does not verify that record (that is E1.3/E1.4).
BUDGET_SCOPE_FIELDS = {
    "global_budget_id",
    "lease_id",
    "budget_id",
    "period_id",
    "Q",
    "P",
}


class MeteringError(ValueError):
    """Raised on malformed policy/attestation or a trust-rule violation."""


# --------------------------------------------------------------------------- #
# Internal validation helpers
# --------------------------------------------------------------------------- #
def _nonempty(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise MeteringError(f"{field} must be a non-empty string")


def _integer(value: Any, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MeteringError(f"{field} must be a non-bool integer")


def _sha256(value: Any, field: str) -> None:
    if not enc.is_sha256(value):
        raise MeteringError(f"{field} must be a sha256:<64 lowercase hex> digest")


def _fp_hex(value: Any, field: str) -> None:
    try:
        enc.fp_from_hex(value)
    except enc.E1EncodingError as exc:
        raise MeteringError(f"{field} must be a canonical Pallas Fp hex: {exc}") from exc


def _uint32(value: Any, field: str) -> None:
    _integer(value, field)
    if not (1 <= value <= enc.MAX_UINT32):
        raise MeteringError(f"{field} must be in [1, 2^32-1]")


def _timestamp(value: Any, field: str) -> None:
    _integer(value, field)
    if value <= 0:
        raise MeteringError(f"{field} must be a positive Unix timestamp")


# --------------------------------------------------------------------------- #
# Metering Policy
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class PolicyEntry:
    """One immutable (tool, schema) -> cost rule."""

    tool_name: str
    tool_schema_hash: str
    cost: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "tool_schema_hash": self.tool_schema_hash,
            "cost": self.cost,
        }


def _parse_entry(raw: Any) -> PolicyEntry:
    if not isinstance(raw, Mapping) or set(raw) != POLICY_ENTRY_FIELDS:
        raise MeteringError("policy entry field set is not exactly the expected three fields")
    _nonempty(raw["tool_name"], "tool_name")
    _sha256(raw["tool_schema_hash"], "tool_schema_hash")
    _uint32(raw["cost"], "cost")
    return PolicyEntry(raw["tool_name"], raw["tool_schema_hash"], raw["cost"])


@dataclass(frozen=True)
class MeteringPolicy:
    """Parsed but NOT trusted policy data.

    This type deliberately carries no verification flag. Trust is represented
    by a distinct :class:`VerifiedMeteringPolicy`, obtainable ONLY as the return
    value of :func:`verify_metering_policy`. Keeping the unverified and verified
    representations as separate types closes the ``dataclasses.replace()`` hole:
    a caller cannot copy a policy, change its fee table, and reuse a stale
    ``_verified=True`` flag.
    """

    version: int
    issuer_id: str
    policy_version: str
    P: str
    entries: tuple[PolicyEntry, ...]
    signature_b64: str

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "issuer_id": self.issuer_id,
            "policy_version": self.policy_version,
            "P": self.P,
            "entries": [entry.as_dict() for entry in self.entries],
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self.unsigned_payload(), "signature_b64": self.signature_b64}


class VerifiedMeteringPolicy:
    """An Issuer-verified policy; the ONLY type cost/issue/verify accept.

    This is intentionally NOT a dataclass: ``dataclasses.replace()`` cannot
    clone it, so there is no public way to manufacture a "verified" policy with
    a modified fee table. It is constructed solely by
    :func:`verify_metering_policy` after the Ed25519 signature check succeeds.

    The object is immutable by convention (private slots, no setters) and keeps
    a private digest that was computed from the exact verified content. Every
    consumer re-checks that the current payload still hashes to that digest, so
    even in-process mutation attempts are detected (fail closed).
    """

    __slots__ = ("_policy", "_digest")

    def __init__(self, policy: MeteringPolicy, digest: str) -> None:
        # Private constructor: callers must go through verify_metering_policy().
        object.__setattr__(self, "_policy", policy)
        object.__setattr__(self, "_digest", digest)

    @property
    def policy(self) -> MeteringPolicy:
        return self._policy

    @property
    def digest(self) -> str:
        return self._digest

    @property
    def P(self) -> str:
        return self._policy.P

    @property
    def entries(self) -> tuple[PolicyEntry, ...]:
        return self._policy.entries

    def unsigned_payload(self) -> dict[str, Any]:
        return self._policy.unsigned_payload()

    def as_dict(self) -> dict[str, Any]:
        return self._policy.as_dict()

    def is_verified(self) -> bool:
        return True

    def __setattr__(self, name: str, value: Any) -> None:
        raise MeteringError("VerifiedMeteringPolicy is immutable")

    def integrity_ok(self) -> bool:
        """Fail closed if the wrapped payload no longer matches the signed digest."""
        try:
            return compute_metering_policy_digest(self._policy) == self._digest
        except (MeteringError, TypeError, ValueError):
            return False


def parse_metering_policy(raw: Any) -> MeteringPolicy:
    """Strictly parse the signed-policy envelope. Does NOT verify the signature."""
    try:
        if isinstance(raw, (str, bytes, bytearray)):
            raw = json.loads(raw)
        if not isinstance(raw, Mapping):
            raise MeteringError("Metering Policy must be a JSON object")
        expected = POLICY_FIELDS | {"signature_b64"}
        if set(raw) != expected:
            raise MeteringError(
                "Metering Policy field set does not match the signed schema"
            )

        version = raw["version"]
        _integer(version, "version")
        if version != 1:
            raise MeteringError("unsupported Metering Policy version")
        _nonempty(raw["issuer_id"], "issuer_id")
        _nonempty(raw["policy_version"], "policy_version")
        _fp_hex(raw["P"], "P")

        entries_raw = raw["entries"]
        if not isinstance(entries_raw, (list, tuple)) or not entries_raw:
            raise MeteringError("policy entries must be a non-empty list")
        entries = tuple(_parse_entry(item) for item in entries_raw)
        seen: set[tuple[str, str]] = set()
        for entry in entries:
            key = (entry.tool_name, entry.tool_schema_hash)
            if key in seen:
                raise MeteringError("duplicate (tool_name, tool_schema_hash) rule")
            seen.add(key)

        signature_b64 = raw["signature_b64"]
        if not isinstance(signature_b64, str) or not signature_b64:
            raise MeteringError("signature_b64 must be a non-empty string")

        return MeteringPolicy(
            version=version,
            issuer_id=raw["issuer_id"],
            policy_version=raw["policy_version"],
            P=raw["P"],
            entries=entries,
            signature_b64=signature_b64,
        )
    except MeteringError:
        raise
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise MeteringError(f"cannot parse Metering Policy: {exc}") from exc


def compute_metering_policy_digest(
    policy: MeteringPolicy | VerifiedMeteringPolicy,
) -> str:
    """D_P = digest of the nested domain/payload; excludes signature_b64."""
    if not isinstance(policy, (MeteringPolicy, VerifiedMeteringPolicy)):
        raise MeteringError("policy must be a MeteringPolicy or VerifiedMeteringPolicy")
    return enc.canonical_digest(POLICY_DOMAIN, policy.unsigned_payload())


def sign_metering_policy(
    issuer_private_key: Ed25519PrivateKey, *,
    issuer_id: str,
    policy_version: str,
    P: str,
    entries: Any,
) -> MeteringPolicy:
    """Assemble and Issuer-sign a Metering Policy, then return it UNSIGNED-state.

    The returned object still requires :func:`verify_metering_policy` with the
    trusted Issuer public key before :func:`compute_cost` will accept it.
    """
    try:
        if not isinstance(issuer_private_key, Ed25519PrivateKey):
            raise MeteringError("issuer_private_key must be an Ed25519 private key")
        _nonempty(issuer_id, "issuer_id")
        _nonempty(policy_version, "policy_version")
        _fp_hex(P, "P")
        if not isinstance(entries, (list, tuple)) or not entries:
            raise MeteringError("entries must be a non-empty list")
        parsed_entries = tuple(_parse_entry(item) for item in entries)
        seen: set[tuple[str, str]] = set()
        for entry in parsed_entries:
            key = (entry.tool_name, entry.tool_schema_hash)
            if key in seen:
                raise MeteringError("duplicate (tool_name, tool_schema_hash) rule")
            seen.add(key)

        unsigned = {
            "version": 1,
            "issuer_id": issuer_id,
            "policy_version": policy_version,
            "P": P,
            "entries": [entry.as_dict() for entry in parsed_entries],
        }
        signature_b64 = b64encode(
            issuer_private_key.sign(
                canonical_json_bytes({"domain": POLICY_DOMAIN, "payload": unsigned})
            )
        )
        return MeteringPolicy(
            version=1,
            issuer_id=issuer_id,
            policy_version=policy_version,
            P=P,
            entries=parsed_entries,
            signature_b64=signature_b64,
        )
    except MeteringError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise MeteringError(f"cannot issue Metering Policy: {exc}") from exc


def verify_metering_policy(
    policy: MeteringPolicy, issuer_public_key: Ed25519PublicKey,
) -> VerifiedMeteringPolicy | None:
    """Verify the Issuer signature and return a sealed verified policy.

    Returns ``None`` on any failure (falsy, so ``if verify_metering_policy(...)``
    still works). The returned :class:`VerifiedMeteringPolicy` is the only value
    accepted by :func:`compute_cost`, :func:`issue_metering_attestation`, and
    :func:`verify_metering_attestation`. Verification binds the exact signed
    content into the object, so a tampered copy cannot inherit trust.
    """
    try:
        if not isinstance(policy, MeteringPolicy):
            return None
        # Re-validate shape defensively (a parsed object is already validated).
        expected = POLICY_FIELDS | {"signature_b64"}
        if set(policy.as_dict()) != expected:
            return None
        if not isinstance(issuer_public_key, Ed25519PublicKey):
            return None
        message = {
            "domain": POLICY_DOMAIN,
            "payload": policy.unsigned_payload(),
        }
        verify_signature(issuer_public_key, policy.signature_b64, message)
        # Bind the exact signed content into a sealed digest at verification time.
        digest_value = enc.canonical_digest(POLICY_DOMAIN, policy.unsigned_payload())
        return VerifiedMeteringPolicy(policy, digest_value)
    except (MeteringError, TypeError, ValueError):
        return None


def compute_cost(
    tool_name: str, schema_hash: str, policy: VerifiedMeteringPolicy,
) -> int:
    """Return the exact signed cost; requires a sealed verified policy object."""
    if not isinstance(policy, VerifiedMeteringPolicy):
        raise MeteringError("policy must be an Issuer-verified VerifiedMeteringPolicy")
    if not policy.integrity_ok():
        raise MeteringError("verified policy content no longer matches its signed digest")
    if not isinstance(tool_name, str) or not tool_name:
        raise MeteringError("tool_name must be a non-empty string")
    _sha256(schema_hash, "tool_schema_hash")
    for entry in policy.entries:
        if entry.tool_name == tool_name and entry.tool_schema_hash == schema_hash:
            _uint32(entry.cost, "cost")
            return entry.cost
    raise MeteringError("tool/schema is not covered by the signed policy")


# --------------------------------------------------------------------------- #
# Trusted cross-layer budget scope (typed upstream input, not verified here)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class BudgetScope:
    """Issuer-assigned cross-layer scope (E1.0 §3.2), carried as trusted input."""

    global_budget_id: str
    lease_id: str
    budget_id: str
    period_id: str
    Q: int
    P: str

    def validate(self) -> None:
        _nonempty(self.global_budget_id, "global_budget_id")
        _nonempty(self.lease_id, "lease_id")
        _fp_hex(self.budget_id, "budget_id")
        _fp_hex(self.period_id, "period_id")
        _uint32(self.Q, "Q")
        _fp_hex(self.P, "P")


# --------------------------------------------------------------------------- #
# Metering Attestation
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class MeteringAttestation:
    """Envelope: 19 business fields + an outer Executor signature."""

    attestation: dict[str, Any]
    signature_b64: str

    def as_dict(self) -> dict[str, Any]:
        return {"attestation": dict(self.attestation), "signature_b64": self.signature_b64}


def _sign_domain_payload(
    payload: dict[str, Any], key: Ed25519PrivateKey, domain: str = ATTESTATION_DOMAIN,
) -> str:
    message = canonical_json_bytes({"domain": domain, "payload": payload})
    return b64encode(key.sign(message))


def compute_metering_quote_digest(attestation: MeteringAttestation) -> str:
    """metering_quote_digest = canonical_digest(ATTESTATION_DOMAIN, payload)."""
    if not isinstance(attestation, MeteringAttestation):
        raise MeteringError("attestation must be a MeteringAttestation")
    if set(attestation.attestation) != ATTESTATION_FIELDS:
        raise MeteringError("attestation field set does not match the signed schema")
    return enc.canonical_digest(ATTESTATION_DOMAIN, attestation.attestation)


def _validate_attestation_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or set(payload) != ATTESTATION_FIELDS:
        raise MeteringError("attestation field set does not match the signed schema")
    result = dict(payload)
    version = result["version"]
    _integer(version, "version")
    if version != 1:
        raise MeteringError("unsupported Metering Attestation version")
    for f in (
        "executor_id", "operation_id", "canonicalization_version", "tool_name",
        "global_budget_id", "lease_id",
    ):
        _nonempty(result[f], f)
    for f in (
        "binding_digest", "executor_authorization_digest", "arguments_digest",
        "tool_schema_hash", "metering_policy_digest",
    ):
        _sha256(result[f], f)
    for f in ("budget_id", "period_id", "P"):
        _fp_hex(result[f], f)
    _uint32(result["Q"], "Q")
    _uint32(result["c"], "c")
    _timestamp(result["issued_at"], "issued_at")
    _timestamp(result["expires_at"], "expires_at")
    if result["issued_at"] >= result["expires_at"]:
        raise MeteringError("attestation validity interval is empty")
    return result


def issue_metering_attestation(
    *,
    executor_private_key: Ed25519PrivateKey,
    executor_id: str,
    operation_id: str,
    binding: ToolCallBinding | Mapping[str, Any],
    authorization: ExecutorAuthorization | Mapping[str, Any],
    tool_name: str,
    tool_schema_hash: str,
    budget_scope: BudgetScope,
    verified_policy: VerifiedMeteringPolicy,
    issued_at: int,
    expires_at: int,
) -> MeteringAttestation:
    """Issue a Metering Attestation with an internally computed ``c``.

    No ``cost``/``c`` parameter exists. Every binding field comes from already
    fixed trusted upstream objects; ``budget_scope`` is typed trusted input.
    """
    try:
        if not isinstance(executor_private_key, Ed25519PrivateKey):
            raise MeteringError("executor_private_key must be an Ed25519 private key")
        if not isinstance(binding, ToolCallBinding):
            binding = ToolCallBinding.from_dict(binding)
        binding.validate()
        auth = (
            authorization
            if isinstance(authorization, ExecutorAuthorization)
            else ExecutorAuthorization.from_dict(authorization)
        )
        if not isinstance(budget_scope, BudgetScope):
            raise MeteringError("budget_scope must be a BudgetScope")
        budget_scope.validate()
        if not isinstance(verified_policy, VerifiedMeteringPolicy):
            raise MeteringError("verified_policy must be an Issuer-verified VerifiedMeteringPolicy")
        if not verified_policy.integrity_ok():
            raise MeteringError("verified_policy content no longer matches its signed digest")
        _nonempty(executor_id, "executor_id")
        _nonempty(operation_id, "operation_id")

        # Cross-check trusted upstream objects; never trust a mismatched field.
        if operation_id != binding.operation_id:
            raise MeteringError("operation_id does not match the fixed binding")
        if tool_name != binding.tool_name or tool_schema_hash != binding.tool_schema_hash:
            raise MeteringError("tool/schema does not match the fixed binding")
        if executor_id != binding.executor_id:
            raise MeteringError("executor_id does not match the fixed binding")
        if (
            budget_scope.global_budget_id != binding.global_budget_id
            or budget_scope.lease_id != binding.lease_id
        ):
            raise MeteringError("budget_scope D10 identifiers do not match the binding")
        if budget_scope.P != verified_policy.P:
            raise MeteringError("budget_scope P does not match the signed policy P")

        cost = compute_cost(tool_name, tool_schema_hash, verified_policy)
        policy_digest = compute_metering_policy_digest(verified_policy)

        payload = {
            "version": 1,
            "executor_id": executor_id,
            "operation_id": operation_id,
            "binding_digest": binding.binding_digest,
            "executor_authorization_digest": auth.authorization_digest,
            "arguments_digest": binding.arguments_digest,
            "canonicalization_version": binding.canonicalization_version,
            "tool_name": tool_name,
            "tool_schema_hash": tool_schema_hash,
            "global_budget_id": budget_scope.global_budget_id,
            "lease_id": budget_scope.lease_id,
            "budget_id": budget_scope.budget_id,
            "period_id": budget_scope.period_id,
            "Q": budget_scope.Q,
            "P": budget_scope.P,
            "c": cost,
            "metering_policy_digest": policy_digest,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        payload = _validate_attestation_payload(payload)
        signature_b64 = _sign_domain_payload(payload, executor_private_key)
        return MeteringAttestation(payload, signature_b64)
    except MeteringError:
        raise
    except (TypeError, ValueError, KeyError) as exc:
        raise MeteringError(f"cannot issue Metering Attestation: {exc}") from exc


def verify_metering_attestation(
    attestation: MeteringAttestation | Mapping[str, Any],
    executor_public_key: Ed25519PublicKey,
    *,
    expected_binding: ToolCallBinding | Mapping[str, Any],
    expected_authorization_digest: str,
    expected_budget_scope: BudgetScope | Mapping[str, Any],
    expected_policy: VerifiedMeteringPolicy,
    now: int,
) -> bool:
    """Verify signature AND every binding/context field. Signature alone is not enough."""
    try:
        if isinstance(attestation, MeteringAttestation):
            envelope = attestation.as_dict()
        else:
            if not isinstance(attestation, Mapping) or set(attestation) != {
                "attestation", "signature_b64"
            }:
                return False
            envelope = dict(attestation)
        payload = _validate_attestation_payload(envelope["attestation"])
        signature_b64 = envelope["signature_b64"]
        if not isinstance(signature_b64, str) or not signature_b64:
            return False

        if not isinstance(executor_public_key, Ed25519PublicKey):
            return False
        binding = (
            expected_binding
            if isinstance(expected_binding, ToolCallBinding)
            else ToolCallBinding.from_dict(expected_binding)
        )
        binding.validate()
        scope = (
            expected_budget_scope
            if isinstance(expected_budget_scope, BudgetScope)
            else BudgetScope(**expected_budget_scope)
        )
        scope.validate()
        if not isinstance(expected_policy, VerifiedMeteringPolicy):
            return False
        if not expected_policy.integrity_ok():
            return False
        # E.0 §3.4: P <-> (metering_policy_digest, policy content). Binding the
        # attestation's P to scope.P and its digest to the policy is NOT enough:
        # scope.P must be the very P that the Issuer assigned to this policy.
        # Without this check a P=7 attestation could carry a validly signed P=8
        # policy digest and still pass every independent comparison.
        if scope.P != expected_policy.P:
            return False
        _sha256(expected_authorization_digest, "expected_authorization_digest")
        _integer(now, "now")

        # 2. Ed25519 signature over the frozen domain/payload message.
        verify_signature(
            executor_public_key,
            signature_b64,
            {"domain": ATTESTATION_DOMAIN, "payload": payload},
        )

        # 3-9. Every binding/identity/context field must equal trusted inputs.
        checks = {
            "executor_id": binding.executor_id,
            "operation_id": binding.operation_id,
            "binding_digest": binding.binding_digest,
            "arguments_digest": binding.arguments_digest,
            "canonicalization_version": binding.canonicalization_version,
            "tool_name": binding.tool_name,
            "tool_schema_hash": binding.tool_schema_hash,
            "global_budget_id": scope.global_budget_id,
            "lease_id": scope.lease_id,
            "budget_id": scope.budget_id,
            "period_id": scope.period_id,
            "Q": scope.Q,
            "P": scope.P,
            "executor_authorization_digest": expected_authorization_digest,
            "metering_policy_digest": compute_metering_policy_digest(expected_policy),
        }
        for field_name, expected in checks.items():
            if payload[field_name] != expected:
                return False

        # 10. Recompute c from the verified policy; never trust the signed c alone.
        recomputed_c = compute_cost(payload["tool_name"], payload["tool_schema_hash"], expected_policy)
        if payload["c"] != recomputed_c:
            return False

        # 11-12. Validity window uses the caller-supplied fixed 'now'.
        if not (0 < payload["issued_at"] < payload["expires_at"]):
            return False
        if not (payload["issued_at"] <= now < payload["expires_at"]):
            return False
        return True
    except (MeteringError, TypeError, ValueError, KeyError):
        return False


__all__ = [
    "POLICY_DOMAIN",
    "ATTESTATION_DOMAIN",
    "POLICY_FIELDS",
    "ATTESTATION_FIELDS",
    "BUDGET_SCOPE_FIELDS",
    "MeteringError",
    "PolicyEntry",
    "MeteringPolicy",
    "VerifiedMeteringPolicy",
    "BudgetScope",
    "MeteringAttestation",
    "parse_metering_policy",
    "sign_metering_policy",
    "verify_metering_policy",
    "compute_metering_policy_digest",
    "compute_cost",
    "issue_metering_attestation",
    "compute_metering_quote_digest",
    "verify_metering_attestation",
]
