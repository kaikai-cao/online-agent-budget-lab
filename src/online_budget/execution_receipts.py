from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import b64encode, canonical_json_bytes, digest, verify_signature


@dataclass(frozen=True)
class ExecutionReceipt:
    payload: dict[str, Any]
    signature_b64: str

    @property
    def receipt_digest(self) -> str:
        return digest({"payload": self.payload, "signature_b64": self.signature_b64})

    def as_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature_b64": self.signature_b64}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ExecutionReceipt":
        if not isinstance(value, Mapping) or set(value) != {"payload", "signature_b64"}:
            raise ValueError("Execution Receipt must contain payload and signature_b64")
        if not isinstance(value["payload"], Mapping) or not isinstance(value["signature_b64"], str):
            raise ValueError("Execution Receipt fields have invalid types")
        return cls(dict(value["payload"]), value["signature_b64"])


def sign_execution_receipt(payload: Mapping[str, Any], key: Ed25519PrivateKey) -> ExecutionReceipt:
    value = dict(payload)
    return ExecutionReceipt(value, b64encode(key.sign(canonical_json_bytes(value))))


def verify_execution_receipt(
    receipt: ExecutionReceipt | Mapping[str, Any], key: Ed25519PublicKey,
    *, expected: Mapping[str, Any] | None = None,
) -> bool:
    try:
        parsed = receipt if isinstance(receipt, ExecutionReceipt) else ExecutionReceipt.from_dict(receipt)
        p = parsed.payload
        required = {
            "receipt_version", "executor_id", "coordinator_id", "global_budget_id", "gateway_id",
            "lease_id", "operation_id", "binding_digest", "budget_receipt_digest", "tool_name",
            "tool_schema_hash", "arguments_digest", "status", "result_digest", "result", "completed_at",
        }
        if set(p) != required or p["receipt_version"] != 1:
            return False
        if p["status"] not in {"SUCCEEDED", "FAILED"}:
            return False
        for field in ("binding_digest", "budget_receipt_digest", "tool_schema_hash", "arguments_digest", "result_digest"):
            if not isinstance(p[field], str) or len(p[field]) != 71 or not p[field].startswith("sha256:"):
                return False
        if not isinstance(p["completed_at"], int) or isinstance(p["completed_at"], bool):
            return False
        if p["result_digest"] != digest({"domain": "agent-tool-result-v1", "result": p["result"]}):
            return False
        if expected and any(p.get(k) != v for k, v in expected.items()):
            return False
        verify_signature(key, parsed.signature_b64, p)
        return True
    except (KeyError, TypeError, ValueError):
        return False
