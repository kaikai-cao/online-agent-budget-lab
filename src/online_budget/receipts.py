from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import b64encode, canonical_json_bytes, digest, verify_signature


@dataclass(frozen=True)
class BudgetReceipt:
    payload: dict[str, Any]
    signature_b64: str

    @property
    def receipt_digest(self) -> str:
        return digest({"payload": self.payload, "signature_b64": self.signature_b64})

    def as_dict(self) -> dict[str, Any]:
        return {"payload": self.payload, "signature_b64": self.signature_b64}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BudgetReceipt":
        if not isinstance(value, Mapping) or set(value) != {"payload", "signature_b64"}:
            raise ValueError("Budget Receipt must contain payload and signature_b64")
        if not isinstance(value["payload"], Mapping) or not isinstance(value["signature_b64"], str):
            raise ValueError("Budget Receipt fields have invalid types")
        return cls(payload=dict(value["payload"]), signature_b64=value["signature_b64"])


def sign_budget_receipt(payload: Mapping[str, Any], key: Ed25519PrivateKey) -> BudgetReceipt:
    value = dict(payload)
    signature = key.sign(canonical_json_bytes(value))
    return BudgetReceipt(value, b64encode(signature))


def verify_budget_receipt(
    receipt: BudgetReceipt | Mapping[str, Any],
    key: Ed25519PublicKey,
    *,
    expected: Mapping[str, Any] | None = None,
) -> bool:
    try:
        parsed = receipt if isinstance(receipt, BudgetReceipt) else BudgetReceipt.from_dict(receipt)
        p = parsed.payload
        required = {
            "receipt_version", "coordinator_id", "coordinator_key_id", "global_budget_id",
            "global_sequence", "gateway_id", "lease_id", "global_lease_grant_digest",
            "execution_grant_digest", "operation_id", "request_digest", "lease_used_count",
            "global_used_count", "committed_at",
        }
        if set(p) != required or p["receipt_version"] != 1:
            return False
        for name in ("global_sequence", "lease_used_count", "global_used_count", "committed_at"):
            if not isinstance(p[name], int) or isinstance(p[name], bool) or p[name] < 1:
                if name == "committed_at" and p[name] == 0:
                    continue
                return False
        for name in ("global_lease_grant_digest", "execution_grant_digest", "request_digest"):
            if not isinstance(p[name], str) or len(p[name]) != 71 or not p[name].startswith("sha256:"):
                return False
        if expected:
            for name, value in expected.items():
                if p.get(name) != value:
                    return False
        verify_signature(key, parsed.signature_b64, p)
        return True
    except (KeyError, TypeError, ValueError):
        return False
