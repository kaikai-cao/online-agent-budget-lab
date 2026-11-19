"""H1 shared protocol: authorization object and action digest.

Both B2 (online authorization query over trusted TLS) and C (locally verified
Ed25519 credential) bind the SAME authorization object fields and use the SAME
action-digest algorithm. This module is the single source of truth for that
canonical form.

Boundaries (H1 is a mechanism-feasibility experiment, not production):
- action_digest binds the *action identity* fields only: executor_id, server_uri,
  tool_name, schema_hash, arguments. It does NOT include jti/issued_at/expires_at
  (those are authorization metadata, signed separately in the C credential).
- canonicalization reuses online_budget.canonical.canonical_json_bytes, which
  rejects non-finite floats and non-JSON values via allow_nan=False.
- domain separation is a fixed prefix field inside the digested object.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from online_budget.canonical import digest

ACTION_DOMAIN = "h1-action-binding-v1"
CREDENTIAL_DOMAIN = "h1-authorization-credential-v1"

# Fields that participate in the action identity / action_digest.
ACTION_FIELDS = ("executor_id", "server_uri", "tool_name", "schema_hash", "arguments")


class H1ProtocolError(ValueError):
    """Raised when an action/authorization object violates the canonical form."""


@dataclass(frozen=True)
class ActionRequest:
    """The untrusted Planner's tool request (identity fields only)."""

    executor_id: str
    server_uri: str
    tool_name: str
    schema_hash: str
    arguments: Mapping[str, Any]


def action_identity(request: ActionRequest | Mapping[str, Any]) -> dict[str, Any]:
    """Extract only the action-identity fields, in canonical form.

    Any extra field a Planner supplies (including a forged ``action_digest``)
    is dropped here. The Executor always recomputes from these identity fields.
    """
    if isinstance(request, ActionRequest):
        data = {
            "executor_id": request.executor_id,
            "server_uri": request.server_uri,
            "tool_name": request.tool_name,
            "schema_hash": request.schema_hash,
            "arguments": dict(request.arguments),
        }
    elif isinstance(request, Mapping):
        missing = [k for k in ACTION_FIELDS if k not in request]
        if missing:
            raise H1ProtocolError(f"action request missing fields: {missing}")
        data = {k: request[k] for k in ACTION_FIELDS}
        if not isinstance(data["arguments"], Mapping):
            raise H1ProtocolError("arguments must be a JSON object")
        data["arguments"] = dict(data["arguments"])
    else:
        raise H1ProtocolError("action request must be ActionRequest or Mapping")
    return data


def compute_action_digest(request: ActionRequest | Mapping[str, Any]) -> str:
    """SHA-256 over canonical-encoded action identity with domain separation.

    Raises H1ProtocolError if arguments contain non-finite floats or non-JSON
    values (canonical_json_bytes enforces allow_nan=False).
    """
    try:
        return digest({"domain": ACTION_DOMAIN, "action": action_identity(request)})
    except ValueError as exc:
        raise H1ProtocolError(f"action digest computation failed: {exc}") from exc


@dataclass(frozen=True)
class AuthorizationObject:
    """The full authorization object both groups bind to."""

    executor_id: str
    server_uri: str
    tool_name: str
    schema_hash: str
    arguments: Mapping[str, Any]
    action_digest: str
    jti: str
    issued_at: float
    expires_at: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "executor_id": self.executor_id,
            "server_uri": self.server_uri,
            "tool_name": self.tool_name,
            "schema_hash": self.schema_hash,
            "arguments": dict(self.arguments),
            "action_digest": self.action_digest,
            "jti": self.jti,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


def build_authorization_object(
    *,
    request: ActionRequest | Mapping[str, Any],
    jti: str,
    issued_at: float,
    expires_at: float,
) -> AuthorizationObject:
    """Build an authorization object from a trusted user-confirmed action.

    Only called by the Authorization Service after user confirmation, never by
    the untrusted Planner.
    """
    identity = action_identity(request)
    return AuthorizationObject(
        executor_id=identity["executor_id"],
        server_uri=identity["server_uri"],
        tool_name=identity["tool_name"],
        schema_hash=identity["schema_hash"],
        arguments=identity["arguments"],
        action_digest=compute_action_digest(identity),
        jti=jti,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def credential_payload(auth: AuthorizationObject | Mapping[str, Any]) -> dict[str, Any]:
    """The exact payload the Authorization Service signs for group C.

    Covers every authorization claim (identity, digest, jti, times) plus issuer /
    audience / key_id / version. The Executor verifies all of these locally.
    """
    data = auth.as_dict() if isinstance(auth, AuthorizationObject) else dict(auth)
    return {
        "domain": CREDENTIAL_DOMAIN,
        "version": 1,
        "issuer": data.pop("issuer", "h1-auth-service"),
        "audience": data.pop("audience", "h1-executor"),
        "key_id": data.pop("key_id", "h1-key-1"),
        **data,
    }
