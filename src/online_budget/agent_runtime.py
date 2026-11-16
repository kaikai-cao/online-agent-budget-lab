from __future__ import annotations

from typing import Any, Mapping

from .adapter import OnlineBudgetExecutionAdapter
from .executor import ToolExecutionDenied, TrustedToolExecutor
from .executor_authorization import (
    ExecutorAuthorization, executor_admission_digest, verify_executor_authorization,
)
from .grants import OnlineLeaseGrant
from .canonical import public_key_bytes
from .tool_binding import ToolCallBinding, build_tool_call_binding, snapshot_arguments


class AgentToolRuntime:
    """Minimal Planner -> Gateway/Coordinator -> trusted local Executor path.

    The planner input is data only. All identities, grants and execution
    boundaries are supplied by trusted runtime configuration.
    """

    def __init__(self, *, gateway_adapter: OnlineBudgetExecutionAdapter, executor: TrustedToolExecutor,
                 online_lease_grant: OnlineLeaseGrant, execution_grant: Mapping[str, Any], executor_id: str,
                 executor_authorization: ExecutorAuthorization | Mapping[str, Any] | None = None) -> None:
        self.gateway_adapter = gateway_adapter
        self.executor = executor
        self.online_lease_grant = online_lease_grant
        self.execution_grant = dict(execution_grant)
        self.executor_id = executor_id
        self.executor_authorization = executor_authorization

    def run_tool_call(self, *, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if (
            self.executor.authorization_policy == "authorization_required"
            and self.executor_authorization is None
        ):
            raise ToolExecutionDenied(
                "Executor Authorization is required by executor policy"
            )
        operation_id = self.execution_grant["operation_id"]
        # Detach planner-owned nested objects before any network call. This exact
        # snapshot is used to build the binding and later passed to dispatch.
        safe_arguments = snapshot_arguments(arguments)
        schema_hash = self.executor.registry.schema_hash(tool_name)
        binding = build_tool_call_binding(
            operation_id=operation_id,
            gateway_id=self.gateway_adapter.client.gateway_id,
            coordinator_id=self.gateway_adapter.coordinator_id,
            online_lease_grant=self.online_lease_grant,
            execution_grant=self.execution_grant,
            tool_name=tool_name,
            tool_schema_hash=schema_hash,
            arguments=safe_arguments,
            executor_id=self.executor_id,
        )
        admission_digest = binding.binding_digest
        if self.executor_authorization is not None:
            try:
                # D10.6: verify against this exact binding's argument digest and
                # canonicalization version BEFORE budget admission. A v2
                # authorization signed for INV-100 cannot authorize INV-999.
                authorized_key = verify_executor_authorization(
                    self.executor_authorization, self.gateway_adapter.issuer_public_key,
                    online_lease_grant=self.online_lease_grant, execution_grant=self.execution_grant,
                    gateway_id=self.gateway_adapter.client.gateway_id,
                    coordinator_id=self.gateway_adapter.coordinator_id, executor_id=self.executor_id,
                    tool_name=tool_name, tool_schema_hash=schema_hash, now=int(self.executor.clock()),
                    expected_arguments_digest=binding.arguments_digest,
                    canonicalization_version=binding.canonicalization_version,
                    require_argument_binding=(
                        self.executor.authorization_policy == "authorization_required"
                    ),
                )
                if public_key_bytes(authorized_key) != public_key_bytes(self.executor.executor_private_key.public_key()):
                    raise ToolExecutionDenied("Executor Authorization names a different Executor key")
                admission_digest = executor_admission_digest(binding.binding_digest, self.executor_authorization)
            except ToolExecutionDenied:
                raise
            except Exception as exc:
                raise ToolExecutionDenied(f"Executor Authorization rejected before budget admission: {exc}") from exc

        safe_arguments = self.executor.prepare_tool_call(
            binding=binding, arguments=safe_arguments, online_lease_grant=self.online_lease_grant,
            execution_grant=self.execution_grant, executor_authorization=self.executor_authorization,
        )
        # Budget admission commits before any tool dispatch. The request digest
        # commits to both the ToolCallBinding and the signed Executor Authorization.
        self.gateway_adapter.consume_for_grant(
            self.execution_grant, operation_id=operation_id, request_digest=admission_digest,
        )
        budget_receipt = self.gateway_adapter.coordinator_receipt_for_operation(operation_id)
        if budget_receipt is None:
            raise RuntimeError("verified Coordinator Budget Receipt is unavailable")
        return self.executor.execute(
            binding=binding, arguments=safe_arguments, online_lease_grant=self.online_lease_grant,
            execution_grant=self.execution_grant, budget_receipt=budget_receipt,
            executor_authorization=self.executor_authorization,
        )
