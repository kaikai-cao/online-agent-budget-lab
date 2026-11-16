from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import b64encode, canonical_json_bytes, digest, is_sha256, verify_signature


class GrantError(ValueError):
    pass


@dataclass(frozen=True)
class ToolPermission:
    tool_name: str
    schema_hash: str

    def as_dict(self) -> dict[str, str]:
        return {"tool_name": self.tool_name, "schema_hash": self.schema_hash}


@dataclass(frozen=True)
class OnlineLeaseGrant:
    """Issuer-signed Online Global Lease Grant v4.

    quota_limit is a per-Lease consumption cap, not a reserved share of G.
    """

    version: int
    issuer_id: str
    grant_id: str
    lease_id: str
    nonce: str
    global_budget_id: str
    quota_limit: int
    issued_at: int
    expires_at: int
    coordinator_audience: str
    allowed_gateway_ids: tuple[str, ...]
    subject_id: str
    context_digest: str
    allowed_tools: tuple[ToolPermission, ...]
    signature_b64: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "issuer_id": self.issuer_id,
            "grant_id": self.grant_id,
            "lease_id": self.lease_id,
            "nonce": self.nonce,
            "global_budget_id": self.global_budget_id,
            "quota_limit": self.quota_limit,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "coordinator_audience": self.coordinator_audience,
            "allowed_gateway_ids": sorted(self.allowed_gateway_ids),
            "subject_id": self.subject_id,
            "context_digest": self.context_digest,
            "allowed_tools": [p.as_dict() for p in sorted(self.allowed_tools, key=lambda x: x.tool_name)],
        }

    @property
    def grant_digest(self) -> str:
        return digest(self.unsigned_dict())

    def as_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature_b64": self.signature_b64}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OnlineLeaseGrant":
        if not isinstance(value, Mapping):
            raise GrantError("Online Lease Grant must be an object")
        expected = {
            "version", "issuer_id", "grant_id", "lease_id", "nonce", "global_budget_id",
            "quota_limit", "issued_at", "expires_at", "coordinator_audience",
            "allowed_gateway_ids", "subject_id", "context_digest", "allowed_tools", "signature_b64",
        }
        if set(value) != expected:
            raise GrantError("Online Lease Grant fields do not match v4 schema")
        tools = value["allowed_tools"]
        gateways = value["allowed_gateway_ids"]
        if not isinstance(tools, list) or not isinstance(gateways, list):
            raise GrantError("allowed_tools and allowed_gateway_ids must be arrays")
        try:
            permissions = tuple(ToolPermission(str(x["tool_name"]), str(x["schema_hash"])) for x in tools)
            return cls(
                version=value["version"], issuer_id=value["issuer_id"], grant_id=value["grant_id"],
                lease_id=value["lease_id"], nonce=value["nonce"], global_budget_id=value["global_budget_id"],
                quota_limit=value["quota_limit"], issued_at=value["issued_at"], expires_at=value["expires_at"],
                coordinator_audience=value["coordinator_audience"], allowed_gateway_ids=tuple(gateways),
                subject_id=value["subject_id"], context_digest=value["context_digest"],
                allowed_tools=permissions, signature_b64=value["signature_b64"],
            )
        except (KeyError, TypeError) as exc:
            raise GrantError(f"malformed Online Lease Grant: {exc}") from exc


def _nonempty(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise GrantError(f"{field} must be a non-empty string")


def validate_online_grant(grant: OnlineLeaseGrant) -> None:
    if not isinstance(grant, OnlineLeaseGrant) or grant.version != 4:
        raise GrantError("Coordinator accepts only Online Lease Grant v4")
    for name in (
        "issuer_id", "grant_id", "lease_id", "nonce", "global_budget_id",
        "coordinator_audience", "subject_id", "context_digest",
    ):
        _nonempty(getattr(grant, name), name)
    for name in ("quota_limit", "issued_at", "expires_at"):
        value = getattr(grant, name)
        if not isinstance(value, int) or isinstance(value, bool):
            raise GrantError(f"{name} must be an integer")
    if grant.quota_limit < 1:
        raise GrantError("quota_limit must be positive")
    if grant.issued_at >= grant.expires_at:
        raise GrantError("grant validity interval is empty")
    if not isinstance(grant.allowed_gateway_ids, tuple) or not grant.allowed_gateway_ids:
        raise GrantError("at least one allowed Gateway ID is required")
    if any(not isinstance(x, str) or not x.strip() for x in grant.allowed_gateway_ids):
        raise GrantError("allowed_gateway_ids contains an invalid identity")
    if len(set(grant.allowed_gateway_ids)) != len(grant.allowed_gateway_ids):
        raise GrantError("allowed_gateway_ids contains duplicates")
    if not isinstance(grant.allowed_tools, tuple) or not grant.allowed_tools:
        raise GrantError("at least one tool permission is required")
    names: set[str] = set()
    for p in grant.allowed_tools:
        if not isinstance(p, ToolPermission):
            raise GrantError("allowed_tools contains an invalid item")
        _nonempty(p.tool_name, "tool_name")
        if p.tool_name in names:
            raise GrantError("allowed_tools contains duplicate tool names")
        names.add(p.tool_name)
        if not is_sha256(p.schema_hash):
            raise GrantError("tool schema_hash must be a sha256 digest")
    if not isinstance(grant.signature_b64, str) or not grant.signature_b64:
        raise GrantError("Grant signature is missing")


def issue_online_lease_grant(
    issuer_private_key: Ed25519PrivateKey,
    *, issuer_id: str, grant_id: str, lease_id: str, nonce: str,
    global_budget_id: str, quota_limit: int, issued_at: int, expires_at: int,
    coordinator_audience: str, allowed_gateway_ids: Sequence[str], subject_id: str,
    context_digest: str, allowed_tools: Sequence[ToolPermission],
) -> OnlineLeaseGrant:
    provisional = OnlineLeaseGrant(
        version=4, issuer_id=issuer_id, grant_id=grant_id, lease_id=lease_id, nonce=nonce,
        global_budget_id=global_budget_id, quota_limit=quota_limit, issued_at=issued_at,
        expires_at=expires_at, coordinator_audience=coordinator_audience,
        allowed_gateway_ids=tuple(sorted(allowed_gateway_ids)), subject_id=subject_id,
        context_digest=context_digest, allowed_tools=tuple(allowed_tools), signature_b64="pending",
    )
    validate_online_grant(provisional)
    signature = issuer_private_key.sign(canonical_json_bytes(provisional.unsigned_dict()))
    signed = OnlineLeaseGrant(**{**provisional.__dict__, "signature_b64": b64encode(signature)})
    return signed


def verify_online_lease_grant(grant: OnlineLeaseGrant, issuer_public_key: Ed25519PublicKey) -> None:
    validate_online_grant(grant)
    try:
        verify_signature(issuer_public_key, grant.signature_b64, grant.unsigned_dict())
    except ValueError as exc:
        raise GrantError("Online Lease Grant signature is invalid") from exc


@dataclass(frozen=True)
class LeaseRevocation:
    version: int
    issuer_id: str
    global_budget_id: str
    revocation_id: str
    lease_id: str
    grant_digest: str
    revoked_at: int
    signature_b64: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "version": self.version, "issuer_id": self.issuer_id,
            "global_budget_id": self.global_budget_id, "revocation_id": self.revocation_id,
            "lease_id": self.lease_id, "grant_digest": self.grant_digest,
            "revoked_at": self.revoked_at,
        }

    @property
    def revocation_digest(self) -> str:
        return digest(self.unsigned_dict())

    def as_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature_b64": self.signature_b64}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LeaseRevocation":
        expected = {"version", "issuer_id", "global_budget_id", "revocation_id", "lease_id", "grant_digest", "revoked_at", "signature_b64"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise GrantError("revocation fields do not match schema")
        return cls(**dict(value))


def issue_revocation(
    issuer_private_key: Ed25519PrivateKey, *, issuer_id: str, global_budget_id: str,
    revocation_id: str, lease_id: str, grant_digest: str, revoked_at: int,
) -> LeaseRevocation:
    p = LeaseRevocation(1, issuer_id, global_budget_id, revocation_id, lease_id, grant_digest, revoked_at, "pending")
    signature = issuer_private_key.sign(canonical_json_bytes(p.unsigned_dict()))
    return LeaseRevocation(**{**p.__dict__, "signature_b64": b64encode(signature)})


def verify_revocation(record: LeaseRevocation, issuer_public_key: Ed25519PublicKey) -> None:
    if not isinstance(record, LeaseRevocation) or record.version != 1:
        raise GrantError("unsupported revocation record")
    for name in ("issuer_id", "global_budget_id", "revocation_id", "lease_id"):
        _nonempty(getattr(record, name), name)
    if not is_sha256(record.grant_digest):
        raise GrantError("revocation grant_digest is invalid")
    if not isinstance(record.revoked_at, int) or isinstance(record.revoked_at, bool):
        raise GrantError("revoked_at must be an integer")
    try:
        verify_signature(issuer_public_key, record.signature_b64, record.unsigned_dict())
    except ValueError as exc:
        raise GrantError("revocation signature is invalid") from exc


def execution_grant_dict(grant: Any) -> dict[str, Any]:
    """Serialize an E4.8.3 LeaseGrant v2 without depending on that repository."""
    if isinstance(grant, Mapping):
        return dict(grant)
    for attr in ("to_dict", "as_dict"):
        method = getattr(grant, attr, None)
        if callable(method):
            value = method()
            if isinstance(value, Mapping):
                return dict(value)
    raise GrantError("execution_grant must be a mapping or expose to_dict()/as_dict()")


def validate_execution_grant_v2(value: Mapping[str, Any], issuer_public_key: Ed25519PublicKey) -> dict[str, Any]:
    expected = {
        "version", "issuer_id", "grant_id", "lease_id", "subject_id", "audience",
        "context_digest", "issued_at", "expires_at", "quota_limit", "nonce", "allowed_tools",
        "parent_authorization_digest", "parent_authorization_nonce", "operation_id", "signature_b64",
    }
    if not isinstance(value, Mapping) or set(value) != expected or value.get("version") != 2:
        raise GrantError("Coordinator accepts only the E4.8.3 Execution Grant v2 schema")
    for name in ("issuer_id", "grant_id", "lease_id", "subject_id", "audience", "context_digest", "nonce", "parent_authorization_nonce", "operation_id"):
        _nonempty(value.get(name), name)
    for name in ("issued_at", "expires_at", "quota_limit"):
        item = value.get(name)
        if not isinstance(item, int) or isinstance(item, bool):
            raise GrantError(f"Execution Grant {name} must be an integer")
    if value["issued_at"] >= value["expires_at"] or value["quota_limit"] < 1:
        raise GrantError("Execution Grant time interval or quota is invalid")
    parent = value["parent_authorization_digest"]
    if not isinstance(parent, str) or len(parent) != 64 or any(ch not in "0123456789abcdef" for ch in parent):
        raise GrantError("parent_authorization_digest must be a lowercase SHA-256 hex digest")
    tools = value["allowed_tools"]
    if not isinstance(tools, list) or not tools:
        raise GrantError("Execution Grant must include allowed_tools")
    seen: set[str] = set()
    normalized = []
    for item in tools:
        if not isinstance(item, Mapping) or set(item) != {"tool_name", "schema_hash"}:
            raise GrantError("Execution Grant tool permission has invalid fields")
        _nonempty(item["tool_name"], "tool_name")
        if item["tool_name"] in seen or not is_sha256(item["schema_hash"]):
            raise GrantError("Execution Grant tool permission is duplicate or malformed")
        seen.add(item["tool_name"])
        normalized.append({"tool_name": item["tool_name"], "schema_hash": item["schema_hash"]})
    unsigned = {k: value[k] for k in expected if k != "signature_b64"}
    unsigned["allowed_tools"] = sorted(normalized, key=lambda x: x["tool_name"])
    try:
        verify_signature(issuer_public_key, value["signature_b64"], unsigned)
    except ValueError as exc:
        raise GrantError("Execution Grant signature is invalid") from exc
    return {**unsigned, "signature_b64": value["signature_b64"]}


def execution_grant_digest(value: Mapping[str, Any]) -> str:
    unsigned = {k: v for k, v in value.items() if k != "signature_b64"}
    return digest(unsigned)
