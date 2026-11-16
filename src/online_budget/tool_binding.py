from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping

from .canonical import canonical_json_bytes, digest, is_sha256
from .grants import OnlineLeaseGrant, execution_grant_digest

CANONICALIZATION_VERSION = "python-canonical-json-v1"
_BINDING_DOMAIN = "agent-tool-call-binding-v1"
_ARGUMENTS_DOMAIN = "agent-tool-arguments-v1"


def _validate_json_value(value: Any, path: str = "$") -> None:
    """Accept a deliberately small, deterministic JSON value profile.

    Floats are rejected (including finite floats) to avoid cross-runtime number
    formatting differences. Integers are restricted to signed 64-bit values.
    """
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            value.encode("utf-8", errors="strict")
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**63) <= value <= (2**63 - 1):
            raise ValueError(f"{path}: integer outside signed 64-bit range")
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floating-point values are not supported")
    if isinstance(value, list):
        for i, item in enumerate(value):
            _validate_json_value(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path}: object keys must be strings")
            key.encode("utf-8", errors="strict")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise ValueError(f"{path}: unsupported JSON value type {type(value).__name__}")



def snapshot_arguments(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Return an independent JSON snapshot for both hashing and dispatch.

    The accepted profile deliberately excludes floats and non-JSON Python
    objects. Serializing and parsing also recursively detaches nested lists and
    dictionaries from caller-owned references. Call this at the trust boundary,
    before any network request or other callback can run.
    """
    if not isinstance(arguments, Mapping):
        raise ValueError("tool arguments must be an object")
    value = dict(arguments)
    _validate_json_value(value)
    try:
        snapshot = json.loads(canonical_json_bytes(value).decode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("tool arguments cannot be represented by the canonical JSON profile") from exc
    if not isinstance(snapshot, dict):
        raise ValueError("tool arguments must encode as a JSON object")
    _validate_json_value(snapshot)
    return snapshot

def arguments_digest(arguments: Mapping[str, Any]) -> str:
    value = snapshot_arguments(arguments)
    return digest({
        "domain": _ARGUMENTS_DOMAIN,
        "canonicalization_version": CANONICALIZATION_VERSION,
        "arguments": value,
    })


@dataclass(frozen=True)
class ToolCallBinding:
    version: int
    operation_id: str
    gateway_id: str
    coordinator_id: str
    global_budget_id: str
    lease_id: str
    global_lease_grant_digest: str
    execution_grant_digest: str
    context_digest: str
    tool_name: str
    tool_schema_hash: str
    arguments_digest: str
    canonicalization_version: str
    executor_id: str

    def payload(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "operation_id": self.operation_id,
            "gateway_id": self.gateway_id,
            "coordinator_id": self.coordinator_id,
            "global_budget_id": self.global_budget_id,
            "lease_id": self.lease_id,
            "global_lease_grant_digest": self.global_lease_grant_digest,
            "execution_grant_digest": self.execution_grant_digest,
            "context_digest": self.context_digest,
            "tool_name": self.tool_name,
            "tool_schema_hash": self.tool_schema_hash,
            "arguments_digest": self.arguments_digest,
            "canonicalization_version": self.canonicalization_version,
            "executor_id": self.executor_id,
        }

    @property
    def binding_digest(self) -> str:
        return digest({"domain": _BINDING_DOMAIN, "binding": self.payload()})

    def as_dict(self) -> dict[str, Any]:
        return {**self.payload(), "binding_digest": self.binding_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolCallBinding":
        expected = {
            "version", "operation_id", "gateway_id", "coordinator_id", "global_budget_id",
            "lease_id", "global_lease_grant_digest", "execution_grant_digest", "context_digest",
            "tool_name", "tool_schema_hash", "arguments_digest", "canonicalization_version",
            "executor_id", "binding_digest",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ValueError("ToolCallBinding fields do not match v1 schema")
        obj = cls(**{k: value[k] for k in expected if k != "binding_digest"})
        obj.validate()
        if value["binding_digest"] != obj.binding_digest:
            raise ValueError("ToolCallBinding digest mismatch")
        return obj

    def validate(self) -> None:
        if self.version != 1:
            raise ValueError("unsupported ToolCallBinding version")
        for name in ("operation_id", "gateway_id", "coordinator_id", "global_budget_id", "lease_id",
                     "tool_name", "executor_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        for name in ("global_lease_grant_digest", "execution_grant_digest", "context_digest",
                     "tool_schema_hash", "arguments_digest"):
            if not is_sha256(getattr(self, name)):
                raise ValueError(f"{name} must be a SHA-256 digest")
        if self.canonicalization_version != CANONICALIZATION_VERSION:
            raise ValueError("unsupported canonicalization version")


def build_tool_call_binding(
    *, operation_id: str, gateway_id: str, coordinator_id: str,
    online_lease_grant: OnlineLeaseGrant, execution_grant: Mapping[str, Any],
    tool_name: str, tool_schema_hash: str, arguments: Mapping[str, Any], executor_id: str,
) -> ToolCallBinding:
    binding = ToolCallBinding(
        version=1,
        operation_id=operation_id,
        gateway_id=gateway_id,
        coordinator_id=coordinator_id,
        global_budget_id=online_lease_grant.global_budget_id,
        lease_id=online_lease_grant.lease_id,
        global_lease_grant_digest=online_lease_grant.grant_digest,
        execution_grant_digest=execution_grant_digest(execution_grant),
        context_digest=online_lease_grant.context_digest,
        tool_name=tool_name,
        tool_schema_hash=tool_schema_hash,
        arguments_digest=arguments_digest(arguments),
        canonicalization_version=CANONICALIZATION_VERSION,
        executor_id=executor_id,
    )
    binding.validate()
    return binding
