from __future__ import annotations

from pathlib import Path
import time
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import digest, public_key_bytes
from .executor_authorization import (
    ExecutorAuthorization, ExecutorAuthorizationError, executor_admission_digest,
    verify_executor_authorization,
)
from .execution_receipts import ExecutionReceipt, sign_execution_receipt, verify_execution_receipt
from .execution_store import ExecutionStore
from .grants import (
    OnlineLeaseGrant, execution_grant_digest, validate_execution_grant_v2,
    verify_online_lease_grant,
)
from .receipts import BudgetReceipt, verify_budget_receipt
from .tool_binding import ToolCallBinding, arguments_digest, snapshot_arguments


class ToolExecutionDenied(ValueError):
    pass


class LocalToolRegistry:
    """Closed registry for the D10.1 deterministic local demonstration tool."""

    def __init__(self) -> None:
        self._tools = {"invoice_review": self._invoice_review}
        self._schemas = {
            "invoice_review": {
                "type": "object", "additionalProperties": False,
                "required": ["invoice_id"],
                "properties": {"invoice_id": {"type": "string", "minLength": 1}},
            }
        }

    def schema(self, name: str) -> dict[str, Any]:
        if name not in self._schemas:
            raise ToolExecutionDenied("tool is not registered")
        return self._schemas[name]

    def schema_hash(self, name: str) -> str:
        return digest({"domain": "agent-tool-schema-v1", "schema": self.schema(name)})

    def validate(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        schema = self.schema(name)
        if not isinstance(arguments, Mapping) or set(arguments) != set(schema["required"]):
            raise ToolExecutionDenied("tool arguments do not match the registered schema")
        invoice_id = arguments.get("invoice_id")
        if not isinstance(invoice_id, str) or not invoice_id.strip():
            raise ToolExecutionDenied("invoice_id must be a non-empty string")
        return {"invoice_id": invoice_id}

    @staticmethod
    def _invoice_review(arguments: Mapping[str, Any]) -> dict[str, Any]:
        invoice_id = arguments["invoice_id"]
        # Deterministic, side-effect-free demonstration result.
        return {
            "invoice_id": invoice_id,
            "decision": "APPROVED",
            "review_id": "review-" + digest({"invoice_id": invoice_id})[7:23],
        }

    def dispatch(self, name: str, arguments: Mapping[str, Any]) -> Any:
        self.validate(name, arguments)
        return self._tools[name](arguments)


class TrustedToolExecutor:
    def __init__(
        self, *, executor_id: str, issuer_public_key: Ed25519PublicKey,
        coordinator_public_key: Ed25519PublicKey, executor_private_key: Ed25519PrivateKey,
        database_path: str | Path, registry: LocalToolRegistry | None = None, clock=None,
        authorization_policy: str = "legacy_allowed",
    ) -> None:
        if authorization_policy not in ("legacy_allowed", "authorization_required"):
            raise ValueError("authorization_policy must be 'legacy_allowed' or 'authorization_required'")
        if not isinstance(executor_id, str) or not executor_id.strip():
            raise ValueError("executor_id must be non-empty")
        self.executor_id = executor_id
        self.issuer_public_key = issuer_public_key
        self.coordinator_public_key = coordinator_public_key
        self.executor_private_key = executor_private_key
        self.registry = registry or LocalToolRegistry()
        self.store = ExecutionStore(database_path)
        self.clock = clock or (lambda: int(time.time()))
        self._authorization_policy = authorization_policy

    @property
    def authorization_policy(self) -> str:
        return self._authorization_policy

    def _verify_grant_binding(
        self, binding: ToolCallBinding, online_grant: OnlineLeaseGrant,
        execution_grant: Mapping[str, Any],
    ) -> dict[str, Any]:
        verify_online_lease_grant(online_grant, self.issuer_public_key)
        execution = validate_execution_grant_v2(execution_grant, self.issuer_public_key)
        now = int(self.clock())
        if now < online_grant.issued_at or now >= online_grant.expires_at:
            raise ToolExecutionDenied("Online Lease Grant is not currently valid")
        if now < execution["issued_at"] or now >= execution["expires_at"]:
            raise ToolExecutionDenied("Execution Grant is not currently valid")
        if execution_grant_digest(execution) != binding.execution_grant_digest:
            raise ToolExecutionDenied("Execution Grant digest differs from ToolCallBinding")
        if online_grant.grant_digest != binding.global_lease_grant_digest:
            raise ToolExecutionDenied("Online Lease Grant digest differs from ToolCallBinding")
        shared_tools = {(p.tool_name, p.schema_hash) for p in online_grant.allowed_tools}
        execution_tools = {(p["tool_name"], p["schema_hash"]) for p in execution["allowed_tools"]}
        if shared_tools != execution_tools:
            raise ToolExecutionDenied("Online and Execution Grants authorize different tool sets")
        if execution["lease_id"] != online_grant.lease_id or execution["context_digest"] != online_grant.context_digest:
            raise ToolExecutionDenied("Online and Execution Grants do not bind the same Lease/context")
        if execution["operation_id"] != binding.operation_id:
            raise ToolExecutionDenied("operation_id differs from Execution Grant")
        if execution["audience"] != binding.gateway_id:
            raise ToolExecutionDenied("Execution Grant audience differs from binding Gateway")
        if binding.gateway_id not in online_grant.allowed_gateway_ids:
            raise ToolExecutionDenied("Gateway is not authorized by the Online Lease Grant")
        if online_grant.global_budget_id != binding.global_budget_id or online_grant.lease_id != binding.lease_id:
            raise ToolExecutionDenied("Lease identity differs from ToolCallBinding")
        if online_grant.context_digest != binding.context_digest:
            raise ToolExecutionDenied("context digest differs from ToolCallBinding")
        if binding.coordinator_id != online_grant.coordinator_audience:
            raise ToolExecutionDenied("Coordinator audience differs from ToolCallBinding")
        if binding.executor_id != self.executor_id:
            raise ToolExecutionDenied("ToolCallBinding targets another Executor")
        if (binding.tool_name, binding.tool_schema_hash) not in shared_tools:
            raise ToolExecutionDenied("tool/schema pair is not authorized by both Grants")
        return execution

    def _verify_executor_authorization(
        self, binding: ToolCallBinding, online_grant: OnlineLeaseGrant,
        execution_grant: Mapping[str, Any],
        executor_authorization: ExecutorAuthorization | Mapping[str, Any] | None,
    ) -> None:
        # None preserves the pre-D10.4 compatibility path. When a D10.4
        # authorization is supplied, the Executor independently verifies it.
        if executor_authorization is None:
            if self._authorization_policy == "authorization_required":
                raise ToolExecutionDenied(
                    "Executor Authorization is required by executor policy"
                )
            return
        try:
            # D10.6: re-check at this dispatch/preflight boundary using the
            # CURRENT ToolCallBinding, so bypassing the Runtime cannot reuse a
            # v2 authorization signed for a different argument set. A v2
            # authorization is only accepted when its signed argument digest and
            # canonicalization version equal this binding's values. Under the
            # authorization_required policy v1 (no argument binding) fails closed.
            authorized_key = verify_executor_authorization(
                executor_authorization, self.issuer_public_key,
                online_lease_grant=online_grant, execution_grant=execution_grant,
                gateway_id=binding.gateway_id, coordinator_id=binding.coordinator_id,
                executor_id=self.executor_id, tool_name=binding.tool_name,
                tool_schema_hash=binding.tool_schema_hash, now=int(self.clock()),
                expected_arguments_digest=binding.arguments_digest,
                canonicalization_version=binding.canonicalization_version,
                require_argument_binding=(
                    self._authorization_policy == "authorization_required"
                ),
            )
        except ExecutorAuthorizationError as exc:
            raise ToolExecutionDenied(f"Executor Authorization rejected: {exc}") from exc
        if public_key_bytes(authorized_key) != public_key_bytes(self.executor_private_key.public_key()):
            raise ToolExecutionDenied("Executor Authorization names a different Executor key")

    def _verify_admission(
        self, binding: ToolCallBinding, online_grant: OnlineLeaseGrant,
        execution_grant: Mapping[str, Any], budget_receipt: BudgetReceipt | Mapping[str, Any],
        executor_authorization: ExecutorAuthorization | Mapping[str, Any] | None = None,
    ) -> BudgetReceipt:
        self._verify_grant_binding(binding, online_grant, execution_grant)
        self._verify_executor_authorization(binding, online_grant, execution_grant, executor_authorization)
        receipt = budget_receipt if isinstance(budget_receipt, BudgetReceipt) else BudgetReceipt.from_dict(budget_receipt)
        expected = {
            "coordinator_id": binding.coordinator_id,
            "global_budget_id": binding.global_budget_id,
            "gateway_id": binding.gateway_id,
            "lease_id": binding.lease_id,
            "global_lease_grant_digest": binding.global_lease_grant_digest,
            "execution_grant_digest": binding.execution_grant_digest,
            "operation_id": binding.operation_id,
            # D10.4 commits to both binding and signed Executor Authorization.
            "request_digest": (
                binding.binding_digest if executor_authorization is None
                else executor_admission_digest(binding.binding_digest, executor_authorization)
            ),
        }
        if not verify_budget_receipt(receipt, self.coordinator_public_key, expected=expected):
            raise ToolExecutionDenied("Coordinator Budget Receipt signature/admission binding is invalid")
        return receipt

    def prepare_tool_call(
        self, *, binding: ToolCallBinding | Mapping[str, Any], arguments: Mapping[str, Any],
        online_lease_grant: OnlineLeaseGrant, execution_grant: Mapping[str, Any],
        executor_authorization: ExecutorAuthorization | Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Preflight authorization and return the detached arguments snapshot.

        AgentToolRuntime calls this before consuming budget. execute() repeats
        these checks independently at the actual dispatch boundary.
        """
        parsed = binding if isinstance(binding, ToolCallBinding) else ToolCallBinding.from_dict(binding)
        parsed.validate()
        self._verify_grant_binding(parsed, online_lease_grant, execution_grant)
        self._verify_executor_authorization(parsed, online_lease_grant, execution_grant, executor_authorization)
        if self.registry.schema_hash(parsed.tool_name) != parsed.tool_schema_hash:
            raise ToolExecutionDenied("registered tool schema has drifted")
        try:
            snapshot = snapshot_arguments(arguments)
            validated = self.registry.validate(parsed.tool_name, snapshot)
            safe_arguments = snapshot_arguments(validated)
        except (TypeError, ValueError) as exc:
            if isinstance(exc, ToolExecutionDenied):
                raise
            raise ToolExecutionDenied(str(exc)) from exc
        if arguments_digest(safe_arguments) != parsed.arguments_digest:
            raise ToolExecutionDenied("actual dispatch arguments differ from ToolCallBinding")
        return safe_arguments

    def execute(
        self, *, binding: ToolCallBinding | Mapping[str, Any], arguments: Mapping[str, Any],
        online_lease_grant: OnlineLeaseGrant, execution_grant: Mapping[str, Any],
        budget_receipt: BudgetReceipt | Mapping[str, Any],
        executor_authorization: ExecutorAuthorization | Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        binding = binding if isinstance(binding, ToolCallBinding) else ToolCallBinding.from_dict(binding)
        binding.validate()
        safe_arguments = self.prepare_tool_call(
            binding=binding, arguments=arguments, online_lease_grant=online_lease_grant,
            execution_grant=execution_grant, executor_authorization=executor_authorization,
        )
        receipt = self._verify_admission(
            binding, online_lease_grant, execution_grant, budget_receipt,
            executor_authorization=executor_authorization,
        )
        now = int(self.clock())

        def make_receipt(state: str, result: Any, error: str | None, completed_at: int) -> dict[str, Any]:
            result_digest = digest({"domain": "agent-tool-result-v1", "result": result})
            payload = {
                "receipt_version": 1,
                "executor_id": self.executor_id,
                "coordinator_id": binding.coordinator_id,
                "global_budget_id": binding.global_budget_id,
                "gateway_id": binding.gateway_id,
                "lease_id": binding.lease_id,
                "operation_id": binding.operation_id,
                "binding_digest": binding.binding_digest,
                "budget_receipt_digest": receipt.receipt_digest,
                "tool_name": binding.tool_name,
                "tool_schema_hash": binding.tool_schema_hash,
                "arguments_digest": binding.arguments_digest,
                "status": state,
                "result_digest": result_digest,
                "result": result,
                "completed_at": completed_at,
            }
            return sign_execution_receipt(payload, self.executor_private_key).as_dict()

        state, result, error, execution_receipt, _created = self.store.execute_once(
            operation_id=binding.operation_id,
            binding_digest=binding.binding_digest,
            binding=binding.as_dict(),
            execute=lambda: self.registry.dispatch(binding.tool_name, safe_arguments),
            make_receipt=make_receipt,
            now=now,
        )
        if not verify_execution_receipt(execution_receipt, self.executor_private_key.public_key(), expected={
            "executor_id": self.executor_id,
            "operation_id": binding.operation_id,
            "binding_digest": binding.binding_digest,
            "budget_receipt_digest": receipt.receipt_digest,
        }):
            raise ToolExecutionDenied("persisted Execution Receipt failed verification")
        return execution_receipt

    def verify_receipt(self, receipt: Mapping[str, Any], *, binding: ToolCallBinding) -> bool:
        return verify_execution_receipt(receipt, self.executor_private_key.public_key(), expected={
            "executor_id": self.executor_id,
            "coordinator_id": binding.coordinator_id,
            "global_budget_id": binding.global_budget_id,
            "gateway_id": binding.gateway_id,
            "lease_id": binding.lease_id,
            "operation_id": binding.operation_id,
            "binding_digest": binding.binding_digest,
        })
