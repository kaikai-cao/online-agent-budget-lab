from __future__ import annotations

from typing import Any, Mapping

from .adapter import OnlineBudgetExecutionAdapter
from .executor import TrustedToolExecutor
from .grants import OnlineLeaseGrant
from .tool_binding import ToolCallBinding, build_tool_call_binding, snapshot_arguments


class AgentToolRuntime:
    """Minimal Planner -> Gateway/Coordinator -> trusted local Executor path.

    The planner input is data only. All identities, grants and execution
    boundaries are supplied by trusted runtime configuration.
    """

    def __init__(self, *, gateway_adapter: OnlineBudgetExecutionAdapter, executor: TrustedToolExecutor,
                 online_lease_grant: OnlineLeaseGrant, execution_grant: Mapping[str, Any], executor_id: str) -> None:
        self.gateway_adapter = gateway_adapter
        self.executor = executor
        self.online_lease_grant = online_lease_grant
        self.execution_grant = dict(execution_grant)
        self.executor_id = executor_id

    def run_tool_call(self, *, tool_name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
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
        safe_arguments = self.executor.prepare_tool_call(
            binding=binding, arguments=safe_arguments, online_lease_grant=self.online_lease_grant,
            execution_grant=self.execution_grant,
        )
        # Budget admission commits before any tool dispatch. A timeout is retried
        # by the Adapter only with this exact operation_id and binding digest.
        self.gateway_adapter.consume_for_grant(
            self.execution_grant, operation_id=operation_id,
            request_digest=binding.binding_digest,
        )
        budget_receipt = self.gateway_adapter.coordinator_receipt_for_operation(operation_id)
        if budget_receipt is None:
            raise RuntimeError("verified Coordinator Budget Receipt is unavailable")
        return self.executor.execute(
            binding=binding, arguments=safe_arguments, online_lease_grant=self.online_lease_grant,
            execution_grant=self.execution_grant, budget_receipt=budget_receipt,
        )
