"""E1.9-C REAL four-gate integration (environment-gated, slow).

This is the strongest end-to-end evidence: it reuses the E1.6 real system
harness (real D10 Coordinator + real Rust e1_service + real Halo2 proof + real
D11 commit + real TrustedToolExecutor.execute_e1 four gates) and threads the
E1.9-C JournalBackedExecutor AROUND it:

    INTENT (Journal Service IPC) -> execute_e1 (real 4 gates + dispatch + v2
    Receipt) -> RESULT (Journal Service IPC) -> local state, then recovery from
    the authoritative Journal without a second dispatch.

Set E1C_REAL_GATE=1 to run (needs the built e1_service.exe).  It is skipped in
the normal suite because the harness boots a real prover and two processes.
Single-process stub tests in test_e1_9_c_integration.py cover orchestration
logic; this file proves the orchestration is compatible with the REAL gate.

Honest boundary: this validates implementation consistency, not a formal
security proof. Journal remains a trusted recorder, not an execution oracle.
"""

from __future__ import annotations

import os
import unittest

from online_budget.canonical import digest
from online_budget.journal_backed_executor import E1CLocalState, JournalBackedExecutor
from online_budget.journal_client import JournalClient
from online_budget.journal_identity import current_process_identity
from online_budget.journal_ipc import NamedPipeClient
from online_budget.journal_service_config import ServiceConfig
from online_budget.tool_binding import ToolCallBinding

from _e1b_helpers import make_config
from test_e1_system import (
    BINDING_DOMAIN, EXE, _SystemHarness, _CountingRegistry, _binding_from_pending,
)


@unittest.skipUnless(
    os.environ.get("E1C_REAL_GATE") == "1" and EXE.exists(),
    "set E1C_REAL_GATE=1 and build e1_service.exe",
)
class RealFourGateIntegration(unittest.TestCase):
    def _journal_client(self, h: _SystemHarness):
        import shutil
        import tempfile
        from pathlib import Path
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import uuid

        d = Path(tempfile.mkdtemp(prefix="e1c-realgate-"))
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        jkey = Ed25519PrivateKey.generate()
        ident = current_process_identity()
        pipe = f"e1c-rg-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        # The Executor public key registered in the Journal must be the one
        # that actually signs the Receipt (h.executor_key).
        config, raw = make_config(
            base_dir=d, journal_key=jkey, executor_key=h.executor_key,
            executor_id=h.executor_id, os_identity=ident.account,
            pipe_name=pipe, allowed_sid=ident.sid,
        )
        from online_budget.journal_service import JournalService
        service = JournalService(config, require_os_backed=False)
        service.start()
        self.addCleanup(service.stop)
        # In-process channel with a simulated caller is used ONLY to keep this
        # test fast; the real Named Pipe + OS identity path is covered by
        # test_e1_9_c_integration.C4RealProcessTests.  Gate semantics here are
        # unaffected (the service still runs the full Receipt v2 verifier).
        from online_budget.journal_identity import CallerIdentity
        from online_budget.journal_ipc import InProcessChannel
        caller = CallerIdentity(sid=ident.sid, account=ident.account,
                                via="TEST_SIMULATED", is_os_backed=False)
        return JournalClient(InProcessChannel(service, caller), executor_id=h.executor_id), d

    def test_G01_real_four_gate_full_chain_with_journal(self):
        h = _SystemHarness(self, registry=_CountingRegistry())
        ex = h.executor()  # real TrustedToolExecutor, e1_required=True
        client, d = self._journal_client(h)
        from online_budget.canonical import private_key_bytes
        from online_budget.canonical import b64encode as _b64
        # Make sure the Journal's registered key equals the executor signing key.
        # (make_config above used h.executor_key already.)
        # A1 boundary: the orchestrator uses the REAL ExecutionStore of the
        # executor, with the sync cursor in the same DB (no separate state DB).
        orch = JournalBackedExecutor(
            executor=ex, client=client, store=ex.store,
            executor_public_key=h.executor_key.public_key(),
        )

        pending = h.run(h.op1)  # real D10 admission + real Halo2 + real D11 commit
        binding = _binding_from_pending(pending)
        receipt = orch.execute_with_journal(
            pending_execution=pending,
            operation_id=h.op1.operation_id,
            binding_digest=binding.binding_digest,
            dispatch_args={
                "online_lease_grant": h.lease,
                "execution_grant": h.op1.execution,
                "executor_authorization": h.op1.authorization,
                "metering_policy": h.policy,
                "budget_scope": h.op1.scope,
            },
        )
        self.assertEqual(ex.counter.dispatch_count, 1)
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        self.assertEqual(receipt["payload"]["receipt_version"], 2)
        # Journal has both phases in order, bound to the original receipt.
        intent = client.get_entry(operation_id=h.op1.operation_id, phase="INTENT")
        result = client.get_entry(operation_id=h.op1.operation_id, phase="RESULT")
        self.assertIsNotNone(intent)
        self.assertIsNotNone(result)
        self.assertLess(intent["seq"], result["seq"])
        self.assertEqual(result["envelope"]["execution_receipt"], receipt)

        # Retry through the orchestrator: original receipt, no second dispatch.
        again = orch.execute_with_journal(
            pending_execution=pending, operation_id=h.op1.operation_id,
            binding_digest=binding.binding_digest, dispatch_args={},
        )
        self.assertEqual(again, receipt)
        self.assertEqual(ex.counter.dispatch_count, 1)

    def test_G02_real_four_gate_recovery_no_redispatch(self):
        from online_budget.execution_store import ExecutionStore

        h = _SystemHarness(self, registry=_CountingRegistry())
        ex = h.executor()
        client, d = self._journal_client(h)
        orch = JournalBackedExecutor(
            executor=ex, client=client, store=ex.store,
            executor_public_key=h.executor_key.public_key(),
        )
        pending = h.run(h.op1)
        binding = _binding_from_pending(pending)
        first = orch.execute_with_journal(
            pending_execution=pending, operation_id=h.op1.operation_id,
            binding_digest=binding.binding_digest,
            dispatch_args={
                "online_lease_grant": h.lease,
                "execution_grant": h.op1.execution,
                "executor_authorization": h.op1.authorization,
                "metering_policy": h.policy,
                "budget_scope": h.op1.scope,
            },
        )
        # Fresh empty ExecutionStore (simulate lost local commit / new instance):
        # Journal still has RESULT, so recovery restores the ORIGINAL receipt
        # into the new store with NO four-gate re-run and NO second dispatch.
        db2 = d / "recovered-store.sqlite3"
        store2 = ExecutionStore(db2)
        orch2 = JournalBackedExecutor(
            executor=ex, client=client, store=store2,
            executor_public_key=h.executor_key.public_key(),
        )
        recovered = orch2.execute_with_journal(
            pending_execution=pending, operation_id=h.op1.operation_id,
            binding_digest=binding.binding_digest, dispatch_args={},
        )
        self.assertEqual(recovered, first)
        self.assertEqual(ex.counter.dispatch_count, 1)  # no re-dispatch
        self.assertEqual(store2.get_receipt(h.op1.operation_id), first)


if __name__ == "__main__":
    unittest.main(verbosity=2)
