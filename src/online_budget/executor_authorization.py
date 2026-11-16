from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import (
    b64encode, canonical_json_bytes, digest, is_sha256,
    public_key_bytes, public_key_from_b64, public_key_digest, verify_signature,
)
from .grants import (
    GrantError, OnlineLeaseGrant, execution_grant_digest,
    validate_execution_grant_v2, verify_online_lease_grant,
)


class ExecutorAuthorizationError(GrantError):
    """Issuer-signed authorization for one exact Executor/tool operation."""


_PAYLOAD_FIELDS = {
    "version", "issuer_id", "authorization_id", "lease_id", "operation_id",
    "execution_grant_digest", "gateway_id", "coordinator_id", "global_budget_id",
    "context_digest", "executor_id", "executor_public_key_b64",
    "executor_public_key_digest", "tool_name", "tool_schema_hash",
    "issued_at", "expires_at",
}

_IDENTITY_FIELDS = (
    "issuer_id", "authorization_id", "lease_id", "operation_id",
    "gateway_id", "coordinator_id", "global_budget_id", "executor_id",
    "executor_public_key_b64", "tool_name",
)


def _nonempty(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ExecutorAuthorizationError(f"{field} must be a non-empty string")


def _integer(value: Any, field: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ExecutorAuthorizationError(f"{field} must be an integer")


def _validate_payload_shape(payload: Mapping[str, Any]) -> None:
    if not isinstance(payload, Mapping) or set(payload) != _PAYLOAD_FIELDS:
        raise ExecutorAuthorizationError("Executor Authorization v1 schema mismatch")

    version = payload["version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise ExecutorAuthorizationError("unsupported Executor Authorization version")

    for field in _IDENTITY_FIELDS:
        _nonempty(payload[field], field)

    for field in (
        "execution_grant_digest", "context_digest",
        "executor_public_key_digest", "tool_schema_hash",
    ):
        if not is_sha256(payload[field]):
            raise ExecutorAuthorizationError(f"{field} must be a SHA-256 digest")

    _integer(payload["issued_at"], "issued_at")
    _integer(payload["expires_at"], "expires_at")

    if payload["issued_at"] >= payload["expires_at"]:
        raise ExecutorAuthorizationError("authorization validity interval is empty")


def _validate_shared_grants(
    online: OnlineLeaseGrant, execution: Mapping[str, Any],
) -> None:
    if (
        execution["issuer_id"] != online.issuer_id
        or execution["grant_id"] != online.grant_id
        or execution["lease_id"] != online.lease_id
        or execution["subject_id"] != online.subject_id
        or execution["context_digest"] != online.context_digest
        or execution["nonce"] != online.nonce
        or execution["quota_limit"] != online.quota_limit
        or execution["issued_at"] != online.issued_at
        or execution["expires_at"] != online.expires_at
    ):
        raise ExecutorAuthorizationError(
            "Online Lease Grant and Execution Grant do not describe the same Lease"
        )

    online_tools = sorted(
        (item.tool_name, item.schema_hash) for item in online.allowed_tools
    )
    execution_tools = sorted(
        (item["tool_name"], item["schema_hash"])
        for item in execution["allowed_tools"]
    )
    if online_tools != execution_tools:
        raise ExecutorAuthorizationError(
            "Online Lease Grant and Execution Grant authorize different tools"
        )


@dataclass(frozen=True)
class ExecutorAuthorization:
    payload: dict[str, Any]
    signature_b64: str

    @property
    def authorization_digest(self) -> str:
        return digest({
            "domain": "executor-authorization-v1",
            "payload": self.payload,
            "signature_b64": self.signature_b64,
        })

    def as_dict(self) -> dict[str, Any]:
        return {
            "payload": dict(self.payload),
            "signature_b64": self.signature_b64,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutorAuthorization":
        if not isinstance(value, Mapping) or set(value) != {
            "payload", "signature_b64"
        }:
            raise ExecutorAuthorizationError(
                "Executor Authorization envelope is malformed"
            )
        if not isinstance(value["payload"], Mapping):
            raise ExecutorAuthorizationError("payload must be an object")
        if not isinstance(value["signature_b64"], str) or not value["signature_b64"]:
            raise ExecutorAuthorizationError("signature_b64 must be non-empty")
        return cls(dict(value["payload"]), value["signature_b64"])


def issue_executor_authorization(
    issuer_private_key: Ed25519PrivateKey, *,
    issuer_id: str,
    authorization_id: str,
    online_lease_grant: OnlineLeaseGrant,
    execution_grant: Mapping[str, Any],
    gateway_id: str,
    coordinator_id: str,
    executor_id: str,
    executor_public_key: Ed25519PublicKey,
    tool_name: str,
    tool_schema_hash: str,
    issued_at: int,
    expires_at: int,
) -> ExecutorAuthorization:
    try:
        verify_online_lease_grant(
            online_lease_grant, issuer_private_key.public_key()
        )
        execution = validate_execution_grant_v2(
            execution_grant, issuer_private_key.public_key()
        )

        for field, value in (
            ("issuer_id", issuer_id),
            ("authorization_id", authorization_id),
            ("gateway_id", gateway_id),
            ("coordinator_id", coordinator_id),
            ("executor_id", executor_id),
            ("tool_name", tool_name),
        ):
            _nonempty(value, field)

        if not isinstance(executor_public_key, Ed25519PublicKey):
            raise ExecutorAuthorizationError(
                "executor_public_key must be an Ed25519 public key"
            )

        if not is_sha256(tool_schema_hash):
            raise ExecutorAuthorizationError("tool_schema_hash is invalid")

        if issuer_id != online_lease_grant.issuer_id:
            raise ExecutorAuthorizationError("Issuer identity mismatch")
        if gateway_id not in online_lease_grant.allowed_gateway_ids:
            raise ExecutorAuthorizationError("Gateway is not authorized by Lease")
        if coordinator_id != online_lease_grant.coordinator_audience:
            raise ExecutorAuthorizationError("Coordinator identity mismatch")

        _validate_shared_grants(online_lease_grant, execution)

        if execution["audience"] != gateway_id:
            raise ExecutorAuthorizationError("Execution Grant Gateway mismatch")

        if (
            tool_name,
            tool_schema_hash,
        ) not in {
            (item.tool_name, item.schema_hash)
            for item in online_lease_grant.allowed_tools
        }:
            raise ExecutorAuthorizationError("tool/schema is not authorized by Online Lease Grant")

        if {
            "tool_name": tool_name,
            "schema_hash": tool_schema_hash,
        } not in execution["allowed_tools"]:
            raise ExecutorAuthorizationError("tool/schema is not authorized by Execution Grant")

        _integer(issued_at, "issued_at")
        _integer(expires_at, "expires_at")

        if (
            issued_at >= expires_at
            or issued_at < online_lease_grant.issued_at
            or expires_at > online_lease_grant.expires_at
            or issued_at < execution["issued_at"]
            or expires_at > execution["expires_at"]
        ):
            raise ExecutorAuthorizationError(
                "authorization validity must be inside both Grant validity intervals"
            )

        pub_b64 = b64encode(public_key_bytes(executor_public_key))
        payload = {
            "version": 1,
            "issuer_id": issuer_id,
            "authorization_id": authorization_id,
            "lease_id": online_lease_grant.lease_id,
            "operation_id": execution["operation_id"],
            "execution_grant_digest": execution_grant_digest(execution),
            "gateway_id": gateway_id,
            "coordinator_id": coordinator_id,
            "global_budget_id": online_lease_grant.global_budget_id,
            "context_digest": online_lease_grant.context_digest,
            "executor_id": executor_id,
            "executor_public_key_b64": pub_b64,
            "executor_public_key_digest": public_key_digest(executor_public_key),
            "tool_name": tool_name,
            "tool_schema_hash": tool_schema_hash,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        _validate_payload_shape(payload)
        signature = issuer_private_key.sign(canonical_json_bytes(payload))
        return ExecutorAuthorization(payload, b64encode(signature))

    except ExecutorAuthorizationError:
        raise
    except (GrantError, KeyError, TypeError, ValueError) as exc:
        raise ExecutorAuthorizationError(
            f"cannot issue Executor Authorization: {exc}"
        ) from exc


def verify_executor_authorization(
    authorization: ExecutorAuthorization | Mapping[str, Any],
    issuer_public_key: Ed25519PublicKey,
    *,
    online_lease_grant: OnlineLeaseGrant,
    execution_grant: Mapping[str, Any],
    gateway_id: str,
    coordinator_id: str,
    executor_id: str,
    tool_name: str,
    tool_schema_hash: str,
    now: int,
) -> Ed25519PublicKey:
    try:
        auth = (
            authorization
            if isinstance(authorization, ExecutorAuthorization)
            else ExecutorAuthorization.from_dict(authorization)
        )
        payload = auth.payload
        _validate_payload_shape(payload)

        if not isinstance(auth.signature_b64, str) or not auth.signature_b64:
            raise ExecutorAuthorizationError("authorization signature is missing")

        verify_signature(issuer_public_key, auth.signature_b64, payload)
        verify_online_lease_grant(online_lease_grant, issuer_public_key)
        execution = validate_execution_grant_v2(
            execution_grant, issuer_public_key
        )
        _validate_shared_grants(online_lease_grant, execution)

        expected = {
            "issuer_id": online_lease_grant.issuer_id,
            "lease_id": online_lease_grant.lease_id,
            "operation_id": execution["operation_id"],
            "execution_grant_digest": execution_grant_digest(execution),
            "gateway_id": gateway_id,
            "coordinator_id": coordinator_id,
            "global_budget_id": online_lease_grant.global_budget_id,
            "context_digest": online_lease_grant.context_digest,
            "executor_id": executor_id,
            "tool_name": tool_name,
            "tool_schema_hash": tool_schema_hash,
        }
        if any(payload[field] != value for field, value in expected.items()):
            raise ExecutorAuthorizationError(
                "Executor Authorization does not match this operation"
            )

        if gateway_id not in online_lease_grant.allowed_gateway_ids:
            raise ExecutorAuthorizationError("Gateway is not authorized by Lease")
        if coordinator_id != online_lease_grant.coordinator_audience:
            raise ExecutorAuthorizationError("Coordinator identity mismatch")
        if execution["audience"] != gateway_id:
            raise ExecutorAuthorizationError("Execution Grant Gateway mismatch")

        if (tool_name, tool_schema_hash) not in {
            (item.tool_name, item.schema_hash)
            for item in online_lease_grant.allowed_tools
        }:
            raise ExecutorAuthorizationError("tool/schema is not authorized by Lease")
        if {
            "tool_name": tool_name,
            "schema_hash": tool_schema_hash,
        } not in execution["allowed_tools"]:
            raise ExecutorAuthorizationError("tool/schema is not authorized by Execution Grant")

        _integer(now, "now")
        if now < payload["issued_at"] or now >= payload["expires_at"]:
            raise ExecutorAuthorizationError(
                "Executor Authorization is not currently valid"
            )
        if (
            payload["issued_at"] < online_lease_grant.issued_at
            or payload["expires_at"] > online_lease_grant.expires_at
            or payload["issued_at"] < execution["issued_at"]
            or payload["expires_at"] > execution["expires_at"]
        ):
            raise ExecutorAuthorizationError(
                "Executor Authorization exceeds Grant validity"
            )

        public_key = public_key_from_b64(payload["executor_public_key_b64"])
        if public_key_digest(public_key) != payload["executor_public_key_digest"]:
            raise ExecutorAuthorizationError("Executor public-key digest mismatch")

        return public_key

    except ExecutorAuthorizationError:
        raise
    except (GrantError, KeyError, TypeError, ValueError) as exc:
        raise ExecutorAuthorizationError(
            f"invalid Executor Authorization: {exc}"
        ) from exc


def executor_admission_digest(binding_digest: str, authorization: ExecutorAuthorization | Mapping[str, Any]) -> str:
    """Commit both the exact ToolCallBinding and signed Executor Authorization."""
    if not is_sha256(binding_digest):
        raise ExecutorAuthorizationError("binding_digest must be a SHA-256 digest")
    auth = authorization if isinstance(authorization, ExecutorAuthorization) else ExecutorAuthorization.from_dict(authorization)
    return digest({
        "domain": "agent-executor-admission-v1",
        "binding_digest": binding_digest,
        "executor_authorization_digest": auth.authorization_digest,
    })
