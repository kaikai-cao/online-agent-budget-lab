"""Test helpers for E1.9-B tests: build valid Receipt v2 and service configs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.canonical import b64encode, digest
from online_budget.execution_receipts import RECEIPT_FIELDS_V2, sign_execution_receipt
from online_budget.journal_service_config import ServiceConfig


def sha(value: str) -> str:
    return "sha256:" + value * 64


def receipt_v2(
    *,
    executor_id: str,
    operation_id: str,
    binding_digest: str,
    result: Any,
    key: Ed25519PrivateKey,
    version: int = 2,
    **overrides: Any,
) -> dict[str, Any]:
    """Build a valid v2 ExecutionReceipt dict (or tamper via overrides/version)."""
    payload: dict[str, Any] = {
        "receipt_version": version,
        "executor_id": executor_id,
        "coordinator_id": "coord-1",
        "global_budget_id": "gb-1",
        "gateway_id": "gw-1",
        "lease_id": "lease-1",
        "operation_id": operation_id,
        "binding_digest": binding_digest,
        "budget_receipt_digest": sha("b"),
        "tool_name": "local.echo",
        "tool_schema_hash": sha("t"),
        "arguments_digest": sha("g"),
        "status": "SUCCEEDED",
        "result_digest": digest({"domain": "agent-tool-result-v1", "result": result}),
        "result": result,
        "completed_at": 1_800_000_000,
        "executor_authorization_digest": sha("e"),
    }
    payload.update(overrides)
    receipt = sign_execution_receipt(payload, key)
    return receipt.as_dict()


def make_binding_payload(
    *, operation_id: str, executor_id: str = "exec-c", tool_name: str = "local.echo"
) -> tuple[dict[str, Any], str]:
    """Build a VALID 14-field ToolCallBinding.payload() and its true digest.

    E1.9-C.1 C4 re-derives request identity from this payload (never from a
    caller claim), so integration tests need a genuine binding payload rather
    than a bare operation_id.  Returns ``(payload, binding_digest)``.
    """
    from online_budget.tool_binding import ToolCallBinding

    binding = ToolCallBinding(
        version=1,
        operation_id=operation_id,
        gateway_id="gw-1",
        coordinator_id="coord-1",
        global_budget_id="gb-1",
        lease_id="lease-1",
        global_lease_grant_digest=sha("a"),
        execution_grant_digest=sha("b"),
        context_digest=sha("c"),
        tool_name=tool_name,
        tool_schema_hash=sha("d"),
        arguments_digest=sha("e"),
        canonicalization_version="python-canonical-json-v1",
        executor_id=executor_id,
    )
    binding.validate()
    return binding.payload(), binding.binding_digest


def result_envelope(
    *, operation_id: str, binding_digest: str, result: Any, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "operation_id": operation_id,
        "binding_digest": binding_digest,
        "result": result,
        "execution_receipt": dict(receipt),
    }


def make_config(
    *,
    base_dir: str | Path,
    journal_key: Ed25519PrivateKey,
    executor_key: Ed25519PrivateKey,
    executor_id: str = "exec-A",
    os_identity: str = "TESTHOST\\exec_acct",
    pipe_name: str = "e1b-test-pipe",
    allowed_sid: str | None = None,
) -> tuple[ServiceConfig, dict[str, Any]]:
    """Create a ServiceConfig and return (config, raw_dict)."""
    from online_budget.canonical import public_key_bytes, private_key_bytes

    journal_sign_b64 = b64encode(private_key_bytes(journal_key))
    journal_verify_b64 = b64encode(public_key_bytes(journal_key.public_key()))
    exec_pub_b64 = b64encode(public_key_bytes(executor_key.public_key()))
    raw = {
        "pipe_name": pipe_name,
        "journal_db_path": str(Path(base_dir) / "journal.sqlite3"),
        "idempotency_db_path": str(Path(base_dir) / "idem.sqlite3"),
        "journal_signing_key_b64": journal_sign_b64,
        "journal_verify_key_b64": journal_verify_b64,
        "allowed_client_sids": [allowed_sid or "S-1-5-32-544"],
        "os_identity_to_executor_ids": {os_identity: [executor_id]},
        "executor_public_keys": {executor_id: exec_pub_b64},
    }
    return ServiceConfig.from_dict(raw, base_dir=base_dir), raw


def write_service_config_json(path: str | Path, raw: Mapping[str, Any]) -> None:
    """Persist a raw service config dict to JSON for the standalone process."""
    Path(path).write_text(json.dumps(dict(raw), ensure_ascii=False), encoding="utf-8")


def simulated_caller(account: str, *, sid: str = "S-1-5-99-TEST") -> Any:
    from online_budget.journal_identity import CallerIdentity

    return CallerIdentity(
        sid=sid, account=account, via="TEST_SIMULATED", is_os_backed=False
    )
