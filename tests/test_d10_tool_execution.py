from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget import (
    CoordinatorHTTPServer, OnlineBudgetClient, OnlineBudgetCoordinator,
    OnlineBudgetExecutionAdapter, ToolPermission, issue_online_lease_grant,
)
from online_budget.canonical import b64encode, canonical_json_bytes, digest
from online_budget.agent_runtime import AgentToolRuntime
from online_budget.executor import LocalToolRegistry, ToolExecutionDenied, TrustedToolExecutor
from online_budget.executor_authorization import (
    executor_admission_digest, issue_executor_authorization,
)
from online_budget.tool_binding import ToolCallBinding, arguments_digest, build_tool_call_binding, snapshot_arguments


class D10ToolExecutionTests(unittest.TestCase):
    NOW = 1_800_000_000
    COORDINATOR_ID = "coordinator-d10-test"
    BUDGET_ID = "budget-d10-test"
    GATEWAY_ID = "gateway-d10-test"
    EXECUTOR_ID = "executor-local-1"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="d10-tool-exec-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.issuer_key = Ed25519PrivateKey.generate()
        self.coordinator_key = Ed25519PrivateKey.generate()
        self.gateway_key = Ed25519PrivateKey.generate()
        self.executor_key = Ed25519PrivateKey.generate()
        self.now = [self.NOW]
        self.registry = LocalToolRegistry()
        self.schema_hash = self.registry.schema_hash("invoice_review")
        self.context_digest = digest({"tenant": "tenant-d10", "purpose": "invoice-review"})
        self.lease = issue_online_lease_grant(
            self.issuer_key,
            issuer_id="issuer-d10", grant_id="grant-d10", lease_id="lease-d10", nonce="nonce-d10",
            global_budget_id=self.BUDGET_ID, quota_limit=5, issued_at=self.NOW - 10,
            expires_at=self.NOW + 3600, coordinator_audience=self.COORDINATOR_ID,
            allowed_gateway_ids=(self.GATEWAY_ID,), subject_id="agent-d10",
            context_digest=self.context_digest,
            allowed_tools=(ToolPermission("invoice_review", self.schema_hash),),
        )
        self.execution = self._make_execution("op-d10-1")
        self.coordinator = OnlineBudgetCoordinator(
            coordinator_id=self.COORDINATOR_ID, global_budget_id=self.BUDGET_ID,
            global_quota_limit=20, issuer_public_key=self.issuer_key.public_key(),
            coordinator_private_key=self.coordinator_key, coordinator_key_id="coord-d10-key",
            database_path=self.root / "coordinator.sqlite3",
            gateways={self.GATEWAY_ID: self.gateway_key.public_key()}, clock=lambda: self.now[0],
        )
        self.server = CoordinatorHTTPServer(("127.0.0.1", 0), self.coordinator)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        client = OnlineBudgetClient(
            base_url=f"http://127.0.0.1:{self.server.server_address[1]}",
            gateway_id=self.GATEWAY_ID, gateway_private_key=self.gateway_key,
            coordinator_public_key=self.coordinator_key.public_key(),
            coordinator_id=self.COORDINATOR_ID, global_budget_id=self.BUDGET_ID,
        )
        self.adapter = OnlineBudgetExecutionAdapter(
            client=client, issuer_public_key=self.issuer_key.public_key(),
            global_budget_id=self.BUDGET_ID, global_quota_limit=20,
            coordinator_id=self.COORDINATOR_ID, receipt_cache_path=self.root / "gateway-cache.sqlite3",
        )
        self.adapter.bind_lease(self.execution, self.lease)
        self.executor = TrustedToolExecutor(
            executor_id=self.EXECUTOR_ID, issuer_public_key=self.issuer_key.public_key(),
            coordinator_public_key=self.coordinator_key.public_key(), executor_private_key=self.executor_key,
            database_path=self.root / "executor.sqlite3", registry=self.registry, clock=lambda: self.now[0],
        )

    def _executor_for_policy(self, policy):
        return TrustedToolExecutor(
            executor_id=self.EXECUTOR_ID,
            issuer_public_key=self.issuer_key.public_key(),
            coordinator_public_key=self.coordinator_key.public_key(),
            executor_private_key=self.executor_key,
            database_path=self.root / f"executor-{policy}.sqlite3",
            registry=self.registry,
            clock=lambda: self.now[0],
            authorization_policy=policy,
        )

    def _stop_server(self):
        if getattr(self, "server", None) is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
            self.server = None

    def _make_execution(self, operation_id):
        unsigned = {
            "version": 2, "issuer_id": self.lease.issuer_id, "grant_id": self.lease.grant_id,
            "lease_id": self.lease.lease_id, "subject_id": self.lease.subject_id,
            "audience": self.GATEWAY_ID, "context_digest": self.lease.context_digest,
            "issued_at": self.lease.issued_at, "expires_at": self.lease.expires_at,
            "quota_limit": self.lease.quota_limit, "nonce": self.lease.nonce,
            "allowed_tools": [p.as_dict() for p in self.lease.allowed_tools],
            "parent_authorization_digest": hashlib.sha256(f"parent:{operation_id}".encode()).hexdigest(),
            "parent_authorization_nonce": f"parent-{operation_id}", "operation_id": operation_id,
        }
        return {**unsigned, "signature_b64": b64encode(self.issuer_key.sign(canonical_json_bytes(unsigned)))}

    def _binding(self, args=None):
        args = args or {"invoice_id": "INV-100"}
        return build_tool_call_binding(
            operation_id=self.execution["operation_id"], gateway_id=self.GATEWAY_ID,
            coordinator_id=self.COORDINATOR_ID, online_lease_grant=self.lease,
            execution_grant=self.execution, tool_name="invoice_review", tool_schema_hash=self.schema_hash,
            arguments=args, executor_id=self.EXECUTOR_ID,
        )

    def _admit(self, binding):
        self.adapter.consume_for_grant(
            self.execution, operation_id=binding.operation_id, request_digest=binding.binding_digest,
        )
        return self.adapter.coordinator_receipt_for_operation(binding.operation_id)

    def test_end_to_end_tool_call_and_signed_receipt(self):
        args = {"invoice_id": "INV-100"}
        binding = self._binding(args)
        budget_receipt = self._admit(binding)
        receipt = self.executor.execute(
            binding=binding, arguments=args, online_lease_grant=self.lease,
            execution_grant=self.execution, budget_receipt=budget_receipt,
        )
        self.assertTrue(self.executor.verify_receipt(receipt, binding=binding))
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        self.assertEqual(receipt["payload"]["result"]["invoice_id"], "INV-100")
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_argument_tampering_is_denied_before_dispatch(self):
        authorized_args = {"invoice_id": "INV-100"}
        binding = self._binding(authorized_args)
        budget_receipt = self._admit(binding)
        with self.assertRaises(ToolExecutionDenied):
            self.executor.execute(
                binding=binding, arguments={"invoice_id": "INV-999"}, online_lease_grant=self.lease,
                execution_grant=self.execution, budget_receipt=budget_receipt,
            )

    def test_extra_argument_is_denied_by_schema(self):
        args = {"invoice_id": "INV-100"}
        binding = self._binding(args)
        budget_receipt = self._admit(binding)
        with self.assertRaises(ToolExecutionDenied):
            self.executor.execute(
                binding=binding, arguments={**args, "admin": True}, online_lease_grant=self.lease,
                execution_grant=self.execution, budget_receipt=budget_receipt,
            )

    def test_schema_drift_is_denied(self):
        args = {"invoice_id": "INV-100"}
        binding = self._binding(args)
        budget_receipt = self._admit(binding)
        self.registry._schemas["invoice_review"]["properties"]["invoice_id"]["minLength"] = 2
        with self.assertRaises(ToolExecutionDenied):
            self.executor.execute(
                binding=binding, arguments=args, online_lease_grant=self.lease,
                execution_grant=self.execution, budget_receipt=budget_receipt,
            )

    def test_wrong_coordinator_receipt_is_denied(self):
        binding = self._binding()
        budget_receipt = self._admit(binding)
        budget_receipt["signature_b64"] = b64encode(Ed25519PrivateKey.generate().sign(canonical_json_bytes(budget_receipt["payload"])))
        with self.assertRaises(ToolExecutionDenied):
            self.executor.execute(
                binding=binding, arguments={"invoice_id": "INV-100"}, online_lease_grant=self.lease,
                execution_grant=self.execution, budget_receipt=budget_receipt,
            )

    def test_exact_replay_returns_same_receipt(self):
        args = {"invoice_id": "INV-100"}
        binding = self._binding(args)
        budget_receipt = self._admit(binding)
        first = self.executor.execute(
            binding=binding, arguments=args, online_lease_grant=self.lease,
            execution_grant=self.execution, budget_receipt=budget_receipt,
        )
        second = self.executor.execute(
            binding=binding, arguments=args, online_lease_grant=self.lease,
            execution_grant=self.execution, budget_receipt=budget_receipt,
        )
        self.assertEqual(first, second)


    def test_concurrent_exact_replay_returns_one_durable_receipt(self):
        args = {"invoice_id": "INV-CONCURRENT"}
        binding = self._binding(args)
        budget_receipt = self._admit(binding)
        clock_lock = threading.Lock()
        ticks = [self.NOW]

        def advancing_clock():
            with clock_lock:
                ticks[0] += 1
                return ticks[0]

        self.executor.clock = advancing_clock

        def invoke(_):
            return self.executor.execute(
                binding=binding, arguments=args, online_lease_grant=self.lease,
                execution_grant=self.execution, budget_receipt=budget_receipt,
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            receipts = list(pool.map(invoke, range(16)))
        self.assertTrue(all(item == receipts[0] for item in receipts))
        self.assertTrue(self.executor.verify_receipt(receipts[0], binding=binding))

    def test_exact_replay_after_executor_restart_returns_persisted_receipt(self):
        args = {"invoice_id": "INV-RESTART"}
        binding = self._binding(args)
        budget_receipt = self._admit(binding)
        first = self.executor.execute(
            binding=binding, arguments=args, online_lease_grant=self.lease,
            execution_grant=self.execution, budget_receipt=budget_receipt,
        )
        restarted = TrustedToolExecutor(
            executor_id=self.EXECUTOR_ID, issuer_public_key=self.issuer_key.public_key(),
            coordinator_public_key=self.coordinator_key.public_key(), executor_private_key=self.executor_key,
            database_path=self.root / "executor.sqlite3", registry=self.registry, clock=lambda: self.now[0],
        )
        second = restarted.execute(
            binding=binding, arguments=args, online_lease_grant=self.lease,
            execution_grant=self.execution, budget_receipt=budget_receipt,
        )
        self.assertEqual(first, second)
        self.assertTrue(restarted.verify_receipt(second, binding=binding))

    def test_runtime_composes_gateway_coordinator_and_executor(self):
        runtime = AgentToolRuntime(
            gateway_adapter=self.adapter, executor=self.executor, online_lease_grant=self.lease,
            execution_grant=self.execution, executor_id=self.EXECUTOR_ID,
        )
        receipt = runtime.run_tool_call(tool_name="invoice_review", arguments={"invoice_id": "INV-100"})
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")

    def test_unauthorized_registered_tool_is_rejected_before_budget_consumption(self):
        self.registry._schemas["other_tool"] = {
            "type": "object", "additionalProperties": False, "required": ["value"],
            "properties": {"value": {"type": "string", "minLength": 1}},
        }
        self.registry._tools["other_tool"] = lambda arguments: {"value": arguments["value"]}
        runtime = AgentToolRuntime(
            gateway_adapter=self.adapter, executor=self.executor, online_lease_grant=self.lease,
            execution_grant=self.execution, executor_id=self.EXECUTOR_ID,
        )
        with self.assertRaises(ToolExecutionDenied):
            runtime.run_tool_call(tool_name="other_tool", arguments={"value": "x"})
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_runtime_dispatch_uses_snapshot_even_if_planner_arguments_change_during_admission(self):
        runtime = AgentToolRuntime(
            gateway_adapter=self.adapter, executor=self.executor, online_lease_grant=self.lease,
            execution_grant=self.execution, executor_id=self.EXECUTOR_ID,
        )
        planner_arguments = {"invoice_id": "INV-SNAPSHOT"}
        original_consume = self.adapter.consume_for_grant

        def mutate_after_binding(*args, **kwargs):
            planner_arguments["invoice_id"] = "INV-MUTATED"
            return original_consume(*args, **kwargs)

        self.adapter.consume_for_grant = mutate_after_binding
        receipt = runtime.run_tool_call(tool_name="invoice_review", arguments=planner_arguments)
        self.assertEqual(receipt["payload"]["result"]["invoice_id"], "INV-SNAPSHOT")
        self.assertEqual(planner_arguments["invoice_id"], "INV-MUTATED")

    def test_argument_snapshot_detaches_nested_mutable_values(self):
        original = {"nested": {"items": ["a", "b"]}}
        snapshot = snapshot_arguments(original)
        original["nested"]["items"].append("c")
        self.assertEqual(snapshot, {"nested": {"items": ["a", "b"]}})
        self.assertNotEqual(arguments_digest(snapshot), arguments_digest(original))

    def test_expired_grant_exact_replay_is_denied_by_policy(self):
        args = {"invoice_id": "INV-EXPIRY"}
        binding = self._binding(args)
        budget_receipt = self._admit(binding)
        first = self.executor.execute(
            binding=binding, arguments=args, online_lease_grant=self.lease,
            execution_grant=self.execution, budget_receipt=budget_receipt,
        )
        self.now[0] = self.lease.expires_at
        with self.assertRaises(ToolExecutionDenied):
            self.executor.execute(
                binding=binding, arguments=args, online_lease_grant=self.lease,
                execution_grant=self.execution, budget_receipt=budget_receipt,
            )
        self.assertEqual(self.executor.store.get_receipt(binding.operation_id), first)
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_canonical_argument_profile_rejects_floats(self):
        with self.assertRaises(ValueError):
            arguments_digest({"amount": 1.25})

    def _make_executor_authorization(self, *, executor_public_key=None, tool_name="invoice_review", schema_hash=None):
        return issue_executor_authorization(
            self.issuer_key, issuer_id=self.lease.issuer_id,
            authorization_id="auth-" + self.execution["operation_id"],
            online_lease_grant=self.lease, execution_grant=self.execution,
            gateway_id=self.GATEWAY_ID, coordinator_id=self.COORDINATOR_ID,
            executor_id=self.EXECUTOR_ID,
            executor_public_key=executor_public_key or self.executor_key.public_key(),
            tool_name=tool_name, tool_schema_hash=schema_hash or self.schema_hash,
            issued_at=self.NOW - 5, expires_at=self.NOW + 300,
        )

    def test_d104_runtime_authorization_is_bound_into_coordinator_receipt(self):
        authorization = self._make_executor_authorization()
        runtime = AgentToolRuntime(
            gateway_adapter=self.adapter, executor=self.executor, online_lease_grant=self.lease,
            execution_grant=self.execution, executor_id=self.EXECUTOR_ID,
            executor_authorization=authorization,
        )
        receipt = runtime.run_tool_call(tool_name="invoice_review", arguments={"invoice_id": "INV-D104"})
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        coordinator_receipt = self.adapter.coordinator_receipt_for_operation(self.execution["operation_id"])
        expected_digest = executor_admission_digest(
            receipt["payload"]["binding_digest"], authorization,
        )
        self.assertEqual(coordinator_receipt["payload"]["request_digest"], expected_digest)
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_d104_wrong_executor_key_is_denied_before_budget_consumption(self):
        wrong_key = Ed25519PrivateKey.generate().public_key()
        authorization = self._make_executor_authorization(executor_public_key=wrong_key)
        runtime = AgentToolRuntime(
            gateway_adapter=self.adapter, executor=self.executor, online_lease_grant=self.lease,
            execution_grant=self.execution, executor_id=self.EXECUTOR_ID,
            executor_authorization=authorization,
        )
        with self.assertRaises(ToolExecutionDenied):
            runtime.run_tool_call(tool_name="invoice_review", arguments={"invoice_id": "INV-D104"})
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_d104_wrong_tool_binding_is_denied_before_budget_consumption(self):
        self.registry._schemas["other_tool"] = {
            "type": "object", "additionalProperties": False, "required": ["value"],
            "properties": {"value": {"type": "string", "minLength": 1}},
        }
        self.registry._tools["other_tool"] = lambda arguments: {"value": arguments["value"]}
        authorization = self._make_executor_authorization()
        runtime = AgentToolRuntime(
            gateway_adapter=self.adapter, executor=self.executor, online_lease_grant=self.lease,
            execution_grant=self.execution, executor_id=self.EXECUTOR_ID,
            executor_authorization=authorization,
        )
        with self.assertRaises(ToolExecutionDenied):
            runtime.run_tool_call(tool_name="other_tool", arguments={"value": "x"})
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_d104_executor_rechecks_authorization_at_dispatch_boundary(self):
        authorization = self._make_executor_authorization(
            executor_public_key=Ed25519PrivateKey.generate().public_key(),
        )
        args = {"invoice_id": "INV-D104-DIRECT"}
        binding = self._binding(args)
        request_digest = executor_admission_digest(binding.binding_digest, authorization)
        self.adapter.consume_for_grant(
            self.execution, operation_id=binding.operation_id, request_digest=request_digest,
        )
        budget_receipt = self.adapter.coordinator_receipt_for_operation(binding.operation_id)
        with self.assertRaises(ToolExecutionDenied):
            self.executor.execute(
                binding=binding, arguments=args, online_lease_grant=self.lease,
                execution_grant=self.execution, budget_receipt=budget_receipt,
                executor_authorization=authorization,
            )


    def test_d104_expired_authorization_is_denied_before_budget_consumption(self):
        authorization = issue_executor_authorization(
            self.issuer_key, issuer_id=self.lease.issuer_id,
            authorization_id="auth-expired-" + self.execution["operation_id"],
            online_lease_grant=self.lease, execution_grant=self.execution,
            gateway_id=self.GATEWAY_ID, coordinator_id=self.COORDINATOR_ID,
            executor_id=self.EXECUTOR_ID, executor_public_key=self.executor_key.public_key(),
            tool_name="invoice_review", tool_schema_hash=self.schema_hash,
            issued_at=self.NOW - 10, expires_at=self.NOW,
        )
        runtime = AgentToolRuntime(
            gateway_adapter=self.adapter, executor=self.executor, online_lease_grant=self.lease,
            execution_grant=self.execution, executor_id=self.EXECUTOR_ID,
            executor_authorization=authorization,
        )
        with self.assertRaises(ToolExecutionDenied):
            runtime.run_tool_call(tool_name="invoice_review", arguments={"invoice_id": "INV-EXPIRED-AUTH"})
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_d104_tampered_authorization_signature_is_denied_before_budget_consumption(self):
        authorization = self._make_executor_authorization()
        tampered = authorization.as_dict()
        tampered["payload"]["authorization_id"] += "-tampered"
        runtime = AgentToolRuntime(
            gateway_adapter=self.adapter, executor=self.executor, online_lease_grant=self.lease,
            execution_grant=self.execution, executor_id=self.EXECUTOR_ID,
            executor_authorization=tampered,
        )
        with self.assertRaises(ToolExecutionDenied):
            runtime.run_tool_call(tool_name="invoice_review", arguments={"invoice_id": "INV-TAMPERED-AUTH"})
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_d104_authorization_for_another_executor_id_is_denied_before_budget_consumption(self):
        authorization = issue_executor_authorization(
            self.issuer_key, issuer_id=self.lease.issuer_id,
            authorization_id="auth-wrong-id-" + self.execution["operation_id"],
            online_lease_grant=self.lease, execution_grant=self.execution,
            gateway_id=self.GATEWAY_ID, coordinator_id=self.COORDINATOR_ID,
            executor_id="different-executor", executor_public_key=self.executor_key.public_key(),
            tool_name="invoice_review", tool_schema_hash=self.schema_hash,
            issued_at=self.NOW - 5, expires_at=self.NOW + 300,
        )
        runtime = AgentToolRuntime(
            gateway_adapter=self.adapter, executor=self.executor, online_lease_grant=self.lease,
            execution_grant=self.execution, executor_id=self.EXECUTOR_ID,
            executor_authorization=authorization,
        )
        with self.assertRaises(ToolExecutionDenied):
            runtime.run_tool_call(tool_name="invoice_review", arguments={"invoice_id": "INV-WRONG-EXECUTOR"})
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)


    def test_required_policy_runtime_rejects_missing_authorization_before_budget(self):
        executor = self._executor_for_policy("authorization_required")
        runtime = AgentToolRuntime(
            gateway_adapter=self.adapter,
            executor=executor,
            online_lease_grant=self.lease,
            execution_grant=self.execution,
            executor_id=self.EXECUTOR_ID,
        )
        with self.assertRaisesRegex(ToolExecutionDenied, "required"):
            runtime.run_tool_call(
                tool_name="invoice_review",
                arguments={"invoice_id": "INV-100"},
            )
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 0)

    def test_required_policy_direct_prepare_rejects_missing_authorization(self):
        executor = self._executor_for_policy("authorization_required")
        with self.assertRaisesRegex(ToolExecutionDenied, "required"):
            executor.prepare_tool_call(
                binding=self._binding(),
                arguments={"invoice_id": "INV-100"},
                online_lease_grant=self.lease,
                execution_grant=self.execution,
            )

    def test_required_policy_direct_execute_rejects_missing_authorization(self):
        executor = self._executor_for_policy("authorization_required")
        with self.assertRaisesRegex(ToolExecutionDenied, "required"):
            executor.execute(
                binding=self._binding(),
                arguments={"invoice_id": "INV-100"},
                online_lease_grant=self.lease,
                execution_grant=self.execution,
                budget_receipt={},
            )

    def test_required_policy_accepts_valid_authorization(self):
        executor = self._executor_for_policy("authorization_required")
        binding = self._binding()
        authorization = self._make_executor_authorization()
        request_digest = executor_admission_digest(
            binding.binding_digest, authorization
        )
        self.adapter.consume_for_grant(
            self.execution,
            operation_id=binding.operation_id,
            request_digest=request_digest,
        )
        budget_receipt = self.adapter.coordinator_receipt_for_operation(
            binding.operation_id
        )
        receipt = executor.execute(
            binding=binding,
            arguments={"invoice_id": "INV-100"},
            online_lease_grant=self.lease,
            execution_grant=self.execution,
            budget_receipt=budget_receipt,
            executor_authorization=authorization,
        )
        self.assertTrue(executor.verify_receipt(receipt, binding=binding))
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        self.assertEqual(self.coordinator.assert_invariants()["global_used_count"], 1)

    def test_unknown_authorization_policy_is_rejected(self):
        with self.assertRaises(ValueError):
            self._executor_for_policy("unknown-policy")

if __name__ == "__main__":
    unittest.main()
