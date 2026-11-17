from __future__ import annotations

from pathlib import Path
import time
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from dataclasses import fields as _dataclass_fields

from .canonical import digest, public_key_bytes
from .e1_receipts import E1ExecutionDenied, verify_e1_transition_receipt
from .e1_runtime import compute_cross_layer_admission_digest
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
from .metering import (
    BudgetScope, MeteringAttestation, compute_metering_quote_digest,
    verify_metering_attestation, verify_metering_policy,
)
from .receipts import BudgetReceipt, verify_budget_receipt
from .tool_binding import ToolCallBinding, arguments_digest, snapshot_arguments

# Fields of ToolCallBinding.payload() (excludes the derived binding_digest).
# Derived from the dataclass so it cannot drift from the frozen schema.
_BINDING_PAYLOAD_FIELDS = frozenset(
    f.name for f in _dataclass_fields(ToolCallBinding) if f.name != "binding_digest"
)


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
        e1_required: bool = False,
        d11_coordinator_public_keys: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> None:
        if authorization_policy not in ("legacy_allowed", "authorization_required"):
            raise ValueError("authorization_policy must be 'legacy_allowed' or 'authorization_required'")
        if not isinstance(executor_id, str) or not executor_id.strip():
            raise ValueError("executor_id must be non-empty")
        if isinstance(e1_required, bool) is False:
            raise ValueError("e1_required must be a bool")
        # E1 strict mode: no fallback to the D10-only path, authorization
        # required, and a trusted D11 Coordinator key table configured.
        if e1_required:
            if authorization_policy != "authorization_required":
                raise ValueError("e1_required requires authorization_policy='authorization_required'")
            if not d11_coordinator_public_keys or not isinstance(d11_coordinator_public_keys, Mapping):
                raise ValueError("e1_required requires a non-empty trusted d11_coordinator_public_keys mapping")
            if not all(
                isinstance(key_id, str) and key_id
                and isinstance(key, Ed25519PublicKey)
                for key_id, key in d11_coordinator_public_keys.items()
            ):
                raise ValueError("d11_coordinator_public_keys values must be Ed25519PublicKey")
        self.executor_id = executor_id
        self.issuer_public_key = issuer_public_key
        self.coordinator_public_key = coordinator_public_key
        self.executor_private_key = executor_private_key
        self.registry = registry or LocalToolRegistry()
        self.store = ExecutionStore(database_path)
        self.clock = clock or (lambda: int(time.time()))
        self._authorization_policy = authorization_policy
        self._e1_required = e1_required
        self._d11_coordinator_public_keys = (
            dict(d11_coordinator_public_keys) if d11_coordinator_public_keys is not None else {}
        )

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

    def _dispatch_and_seal(
        self, *, binding: ToolCallBinding, safe_arguments: dict[str, Any],
        receipt: BudgetReceipt, authorization_digest: str | None,
    ) -> dict[str, Any]:
        """Shared dispatch + D10 Execution Receipt v2 sealing (fifth relation).

        Reached ONLY after the caller has verified its full admission chain:
        the legacy D10 path verifies ``request_digest = executor_admission_digest``
        in :meth:`_verify_admission`; the E1 path independently verifies
        ``request_digest = D_E`` before calling here. This helper never decides
        the admission digest -- it only seals and verifies the execution result,
        committing ``budget_receipt_digest = receipt.receipt_digest`` (E0 §6.2.1
        fifth relation) and, for v2, the verified authorization digest.
        """
        now = int(self.clock())

        def make_receipt(state: str, result: Any, error: str | None, completed_at: int) -> dict[str, Any]:
            result_digest = digest({"domain": "agent-tool-result-v1", "result": result})
            payload = {
                "receipt_version": 1 if authorization_digest is None else 2,
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
            if authorization_digest is not None:
                payload["executor_authorization_digest"] = authorization_digest
            return sign_execution_receipt(payload, self.executor_private_key).as_dict()

        state, result, error, execution_receipt, _created = self.store.execute_once(
            operation_id=binding.operation_id,
            binding_digest=binding.binding_digest,
            binding=binding.as_dict(),
            execute=lambda: self.registry.dispatch(binding.tool_name, safe_arguments),
            make_receipt=make_receipt,
            now=now,
        )
        expected = {
            "executor_id": self.executor_id,
            "operation_id": binding.operation_id,
            "binding_digest": binding.binding_digest,
            "budget_receipt_digest": receipt.receipt_digest,
        }
        # D10.7: ExecutionStore deduplicates on operation_id + binding_digest
        # only. On an idempotent retry it returns the stored receipt verbatim,
        # which may have been produced under a *different* authorization. Bind
        # the returned receipt to the authorization used in this call, so a
        # valid receipt for authorization A cannot be presented as the result
        # of an execution claimed to use authorization B. This is a verification
        # constraint only; the ExecutionStore schema/API is untouched.
        if authorization_digest is not None:
            expected["executor_authorization_digest"] = authorization_digest
        if not verify_execution_receipt(
            execution_receipt, self.executor_private_key.public_key(), expected=expected,
        ):
            raise ToolExecutionDenied("persisted Execution Receipt failed verification")
        return execution_receipt

    def execute(
        self, *, binding: ToolCallBinding | Mapping[str, Any], arguments: Mapping[str, Any],
        online_lease_grant: OnlineLeaseGrant, execution_grant: Mapping[str, Any],
        budget_receipt: BudgetReceipt | Mapping[str, Any],
        executor_authorization: ExecutorAuthorization | Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self._e1_required:
            raise ToolExecutionDenied(
                "E1 mode: plain execute() is disabled; only execute_e1() may dispatch"
            )
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
        # D10.7: the receipt must commit to the exact ExecutorAuthorization that
        # was actually verified and used for this execution. Callers never
        # supply a digest themselves.
        if executor_authorization is None:
            authorization_digest = None
        else:
            auth = (
                executor_authorization
                if isinstance(executor_authorization, ExecutorAuthorization)
                else ExecutorAuthorization.from_dict(executor_authorization)
            )
            authorization_digest = auth.authorization_digest
        return self._dispatch_and_seal(
            binding=binding, safe_arguments=safe_arguments, receipt=receipt,
            authorization_digest=authorization_digest,
        )

    def execute_e1(
        self, *, pending_execution: Any, online_lease_grant: OnlineLeaseGrant,
        execution_grant: Mapping[str, Any],
        executor_authorization: ExecutorAuthorization | Mapping[str, Any],
        metering_policy: Any, budget_scope: BudgetScope | Mapping[str, Any],
    ) -> dict[str, Any]:
        """E1.5 final execution gate: verify all four pre-dispatch gates, then dispatch.

        ``pending_execution`` from E1.4 is UNTRUSTED: its binding is rebuilt from
        the raw payload, and the cross-layer digest / quote digest / D11 receipt
        are all re-derived or independently verified here, never taken on faith.
        ``now`` comes from this Executor's own trusted ``clock()``. No dispatch
        occurs until every gate passes. The fifth E0 §6.2.1 relation (Execution
        Receipt commits the Budget Receipt digest) is verified after execution
        by :meth:`_dispatch_and_seal`.
        """
        if not self._e1_required:
            raise ToolExecutionDenied("execute_e1 requires an E1-configured Executor")
        if executor_authorization is None:
            raise ToolExecutionDenied("E1 requires an Executor Authorization (v2)")
        now = int(self.clock())

        pending = pending_execution
        # Gate 1a: rebuild the ToolCallBinding from untrusted PendingExecution
        # data. No caller-supplied binding digest is accepted -- it is derived
        # from the payload fields, so a tampered field cannot be "signed over".
        raw_binding = getattr(pending, "binding", None)
        if not isinstance(raw_binding, Mapping) or set(raw_binding) != _BINDING_PAYLOAD_FIELDS:
            raise ToolExecutionDenied("E1 PendingExecution binding is malformed")
        try:
            binding = ToolCallBinding(**{name: raw_binding[name] for name in _BINDING_PAYLOAD_FIELDS})
            binding.validate()
        except (TypeError, ValueError) as exc:
            raise ToolExecutionDenied("E1 PendingExecution binding is invalid") from exc
        if getattr(pending, "operation_id", None) != binding.operation_id:
            raise ToolExecutionDenied("E1 PendingExecution operation_id differs from binding")
        if getattr(pending, "tool_name", None) != binding.tool_name:
            raise ToolExecutionDenied("E1 PendingExecution tool_name differs from binding")
        arguments = getattr(pending, "arguments", None)
        if not isinstance(arguments, Mapping):
            raise ToolExecutionDenied("E1 PendingExecution arguments are malformed")
        # Gate 1b: re-verify Online/Execution Grants, Executor Authorization v2,
        # tool schema and the argument/binding digest via the D10 preflight.
        # With e1_required=True the policy is authorization_required, so v1
        # (no argument binding) is rejected here.
        try:
            safe_arguments = self.prepare_tool_call(
                binding=binding, arguments=arguments,
                online_lease_grant=online_lease_grant, execution_grant=execution_grant,
                executor_authorization=executor_authorization,
            )
        except (ToolExecutionDenied, ExecutorAuthorizationError) as exc:
            raise ToolExecutionDenied(f"E1 grant/authorization gate failed: {exc}") from exc

        # Authorization digest is derived from the REAL verified authorization
        # object, never from a value carried in the untrusted pending context.
        auth = (
            executor_authorization
            if isinstance(executor_authorization, ExecutorAuthorization)
            else ExecutorAuthorization.from_dict(executor_authorization)
        )

        # Gate 2: Metering Policy Issuer signature + Metering Attestation
        # Executor signature and every binding/context/validity field.
        verified_policy = verify_metering_policy(metering_policy, self.issuer_public_key)
        if verified_policy is None:
            raise ToolExecutionDenied("E1 Metering Policy signature is not trusted")
        raw_attestation = getattr(pending, "metering_attestation", None)
        if not isinstance(raw_attestation, Mapping) or set(raw_attestation) != {
            "attestation", "signature_b64"
        }:
            raise ToolExecutionDenied("E1 Metering Attestation envelope is malformed")
        try:
            attestation = MeteringAttestation(
                attestation=dict(raw_attestation["attestation"]),
                signature_b64=raw_attestation["signature_b64"],
            )
        except (TypeError, ValueError) as exc:
            raise ToolExecutionDenied("E1 Metering Attestation is invalid") from exc
        # budget_scope D10 identifiers must match the verified binding (the
        # class is Issuer-supplied trusted context, bound to this operation).
        scope = (
            budget_scope if isinstance(budget_scope, BudgetScope)
            else BudgetScope(**budget_scope)
        )
        scope.validate()
        if scope.global_budget_id != binding.global_budget_id or scope.lease_id != binding.lease_id:
            raise ToolExecutionDenied("E1 budget_scope D10 identifiers differ from binding")
        try:
            att_ok = verify_metering_attestation(
                attestation, self.executor_private_key.public_key(),
                expected_binding=binding,
                expected_authorization_digest=auth.authorization_digest,
                expected_budget_scope=scope,
                expected_policy=verified_policy,
                now=now,
            )
        except (TypeError, ValueError):
            att_ok = False
        if not att_ok:
            raise ToolExecutionDenied("E1 Metering Attestation verification failed")

        # Gate 3: recompute quote digest and D_E, then verify the D10 Budget
        # Receipt's request_digest == D_E (NOT the legacy admission digest).
        quote_digest = compute_metering_quote_digest(attestation)
        d_e = compute_cross_layer_admission_digest(
            binding.binding_digest, auth.authorization_digest, quote_digest
        )
        raw_budget_receipt = getattr(pending, "d10_budget_receipt", None)
        try:
            budget_receipt = (
                raw_budget_receipt if isinstance(raw_budget_receipt, BudgetReceipt)
                else BudgetReceipt.from_dict(raw_budget_receipt)
            )
        except (TypeError, ValueError) as exc:
            raise ToolExecutionDenied("E1 D10 Budget Receipt is malformed") from exc
        expected_receipt = {
            "coordinator_id": binding.coordinator_id,
            "global_budget_id": binding.global_budget_id,
            "gateway_id": binding.gateway_id,
            "lease_id": binding.lease_id,
            "global_lease_grant_digest": binding.global_lease_grant_digest,
            "execution_grant_digest": binding.execution_grant_digest,
            "operation_id": binding.operation_id,
            "request_digest": d_e,
        }
        if not verify_budget_receipt(
            budget_receipt, self.coordinator_public_key, expected=expected_receipt
        ):
            raise ToolExecutionDenied("E1 D10 Budget Receipt signature or request_digest=D_E is invalid")

        # Gate 4: independently verify the D11 Transition Receipt against the
        # trusted Coordinator key table and the re-derived expected fields.
        try:
            verify_e1_transition_receipt(
                getattr(pending, "d11_transition_receipt", None),
                trusted_coordinator_public_keys=self._d11_coordinator_public_keys,
                expected_operation_id=binding.operation_id,
                expected_binding_digest=binding.binding_digest,
                expected_metering_quote_digest=quote_digest,
                expected_budget_id=scope.budget_id,
                expected_period_id=scope.period_id,
            )
        except E1ExecutionDenied as exc:
            raise ToolExecutionDenied(f"E1 D11 Transition Receipt rejected: {exc}") from exc

        # All four gates passed: dispatch once and seal the D10 Execution
        # Receipt v2 (which commits both the Budget Receipt digest and the
        # verified authorization digest).
        return self._dispatch_and_seal(
            binding=binding, safe_arguments=safe_arguments, receipt=budget_receipt,
            authorization_digest=auth.authorization_digest,
        )

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
