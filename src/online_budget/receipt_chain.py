from __future__ import annotations

from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import b64encode, canonical_json_bytes, digest, verify_signature
from .receipts import BudgetReceipt, verify_budget_receipt


def _receipt_digest(value: Mapping[str, Any]) -> str:
    return digest({"payload": dict(value["payload"]), "signature_b64": value["signature_b64"]})


def build_online_receipt_chain(
    gateway_execution_receipt: Mapping[str, Any],
    coordinator_receipt: BudgetReceipt | Mapping[str, Any],
    gateway_private_key: Ed25519PrivateKey,
    coordinator_public_key: Ed25519PublicKey,
) -> dict[str, Any]:
    """Create an extra Gateway signature linking the two independently signed receipts."""
    budget = coordinator_receipt if isinstance(coordinator_receipt, BudgetReceipt) else BudgetReceipt.from_dict(coordinator_receipt)
    if not verify_budget_receipt(budget, coordinator_public_key):
        raise ValueError("Coordinator Budget Receipt failed verification")
    try:
        gateway_payload = dict(gateway_execution_receipt["payload"])
        gateway_signature = gateway_execution_receipt["signature_b64"]
        verify_signature(gateway_private_key.public_key(), gateway_signature, gateway_payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Gateway execution receipt failed verification") from exc
    bp = budget.payload
    expected = {
        "gateway_id": bp["gateway_id"],
        "global_budget_id": bp["global_budget_id"],
        "lease_id": bp["lease_id"],
        "global_lease_grant_digest": bp["global_lease_grant_digest"],
        "operation_id": bp["operation_id"],
        "request_digest": bp["request_digest"],
        "global_sequence": bp["global_sequence"],
        "budget_counter_value": bp["global_sequence"],
        "lease_used_count": bp["lease_used_count"],
    }
    for name, value in expected.items():
        if gateway_payload.get(name) != value:
            raise ValueError(f"Gateway and Coordinator receipts differ on {name}")
    link_payload = {
        "link_version": 1,
        "gateway_id": bp["gateway_id"],
        "coordinator_id": bp["coordinator_id"],
        "global_budget_id": bp["global_budget_id"],
        "lease_id": bp["lease_id"],
        "global_lease_grant_digest": bp["global_lease_grant_digest"],
        "operation_id": bp["operation_id"],
        "request_digest": bp["request_digest"],
        "global_sequence": bp["global_sequence"],
        "coordinator_receipt_digest": budget.receipt_digest,
        "gateway_execution_receipt_digest": _receipt_digest(gateway_execution_receipt),
    }
    signature = gateway_private_key.sign(canonical_json_bytes(link_payload))
    return {"payload": link_payload, "signature_b64": b64encode(signature)}


def verify_online_receipt_chain(
    link: Mapping[str, Any],
    gateway_execution_receipt: Mapping[str, Any],
    coordinator_receipt: BudgetReceipt | Mapping[str, Any],
    gateway_public_key: Ed25519PublicKey,
    coordinator_public_key: Ed25519PublicKey,
) -> bool:
    try:
        if not verify_budget_receipt(coordinator_receipt, coordinator_public_key):
            return False
        bp = coordinator_receipt.payload if isinstance(coordinator_receipt, BudgetReceipt) else coordinator_receipt["payload"]
        gp = gateway_execution_receipt["payload"]
        verify_signature(gateway_public_key, gateway_execution_receipt["signature_b64"], gp)
        lp = link["payload"]
        expected_link_fields = {
            "link_version", "gateway_id", "coordinator_id", "global_budget_id", "lease_id",
            "global_lease_grant_digest", "operation_id", "request_digest", "global_sequence",
            "coordinator_receipt_digest", "gateway_execution_receipt_digest",
        }
        if link.keys() != {"payload", "signature_b64"} or not isinstance(lp, Mapping) or set(lp) != expected_link_fields or lp.get("link_version") != 1:
            return False
        if lp["coordinator_receipt_digest"] != _receipt_digest(
            coordinator_receipt.as_dict() if isinstance(coordinator_receipt, BudgetReceipt) else coordinator_receipt
        ):
            return False
        if lp["gateway_execution_receipt_digest"] != _receipt_digest(gateway_execution_receipt):
            return False
        if lp.get("coordinator_id") != bp.get("coordinator_id"):
            return False
        for name in (
            "gateway_id", "global_budget_id", "lease_id", "global_lease_grant_digest",
            "operation_id", "request_digest", "global_sequence",
        ):
            if lp.get(name) != bp.get(name):
                return False
        for name, expected in (
            ("gateway_id", bp["gateway_id"]),
            ("global_budget_id", bp["global_budget_id"]),
            ("lease_id", bp["lease_id"]),
            ("global_lease_grant_digest", bp["global_lease_grant_digest"]),
            ("operation_id", bp["operation_id"]),
            ("request_digest", bp["request_digest"]),
            ("global_sequence", bp["global_sequence"]),
            ("budget_counter_value", bp["global_sequence"]),
            ("lease_used_count", bp["lease_used_count"]),
        ):
            if gp.get(name) != expected:
                return False
        verify_signature(gateway_public_key, link["signature_b64"], lp)
        return True
    except (KeyError, TypeError, ValueError, InvalidSignature):
        return False
