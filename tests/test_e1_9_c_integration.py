"""E1.9-C / C1 integration tests (Journal Service <-> Executor chain).

Layers, kept strictly separate (E1.9-C task §4):
  * In-process orchestration tests: a stub executor drives a REAL ExecutionStore
    transaction with the frozen ``execute_once`` path (including the
    ``before_store_commit`` RESULT hook), plus a REAL E1.9-B JournalService behind
    InProcessChannel.  These prove C1/C2/C3/C4 ordering, idempotency, recovery,
    G2 three-state, BEHIND replay and fail-closed deterministically and fast.
    InProcessChannel is TEST-ONLY, never a production identity boundary (E0 §9.3).
  * Environment-gated REAL Named Pipe + standalone process test (E1C_REAL_IPC=1):
    cross-process IPC with OS-backed identity, same orchestration object.
  * Environment-gated REAL four-gate test lives in test_e1_9_c_real_gate.py.

E1.9-C.1 (baseline 309e465) correction coverage:
  * C1: RESULT appended (before_store_commit) strictly BEFORE the local
    ExecutionStore insert/commit -- proven by a commit-failure crash hook.
  * C2: A1 write lock is on the REAL ExecutionStore DB (concurrency test).
  * C3: G2 BEHIND performs real seq-by-seq replay with validation; no dispatch.
  * C4: request identity is re-derived from the pending binding payload and
    cross-checked before any INTENT.

Honest boundary: Journal is a trusted recorder, not an execution-proof oracle.
Recovery returns the original signed Receipt; no re-signing.  No G1b / exactly-
once / execution-truth claim.  These tests are not a formal security proof.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any

from online_budget.execution_store import ExecutionStore
from online_budget.journal_backed_executor import (
    E1CFailClosed,
    E1CIntegrityFailure,
    E1CReceiptInvalid,
    E1CRollbackSuspected,
    E1CStateDiverged,
    E1CLocalState,
    JournalBackedExecutor,
    derive_request_identity,
    judge_g2_state,
    recover_result_from_entry,
)
from online_budget.journal_client import JournalClient, JournalClientError
from online_budget.journal_identity import CallerIdentity
from online_budget.journal_ipc import InProcessChannel, NamedPipeClient
from online_budget.journal_service import JournalService

from _e1b_helpers import (
    make_binding_payload, make_config, receipt_v2, result_envelope, write_service_config_json,
)

EXEC_ID = "exec-c"
RESULT = {"value": 42, "echo": "ok"}


class _Pending:
    """Minimal stand-in with a REAL 14-field binding payload for C4."""

    def __init__(self, operation_id: str, *, executor_id: str = EXEC_ID) -> None:
        self.operation_id = operation_id
        self.binding, self.binding_digest_value = make_binding_payload(
            operation_id=operation_id, executor_id=executor_id
        )

    @property
    def binding_digest(self) -> str:
        return self.binding_digest_value


class _StubGateExecutor:
    """Stands in for TrustedToolExecutor's four gates + dispatch + seal.

    It drives a REAL ExecutionStore through ``execute_once`` with the A1
    ``store_con`` and ``before_store_commit`` (RESULT hook), so C1 ordering is
    genuinely exercised.  It returns a REAL Receipt v2 signed by the registered
    executor key, counts dispatches, and supports crash injection at each window.
    """

    def __init__(self, *, key, store: ExecutionStore, executor_id: str = EXEC_ID) -> None:
        self.key = key
        self.store = store
        self.executor_id = executor_id
        self.dispatch_count = 0
        self.fail_gate = False
        self.crash_after_dispatch_before_result = False  # before_store_commit hook raises
        self.crash_after_result_before_local = False     # RESULT appended, local insert raises

    def execute_e1(self, *, pending_execution: Any, store_con=None,
                   before_store_commit=None, **kwargs) -> dict[str, Any]:
        if self.fail_gate:
            raise RuntimeError("test: final gate refused")
        op = getattr(pending_execution, "operation_id")
        binding_digest = getattr(pending_execution, "binding_digest")

        def do_dispatch():
            self.dispatch_count += 1
            return dict(RESULT)

        def make_receipt(state, result, error, completed_at):
            return receipt_v2(
                executor_id=self.executor_id, operation_id=op,
                binding_digest=binding_digest, result=result, key=self.key,
                status=state,
            )

        def before_commit(receipt):
            if self.crash_after_dispatch_before_result:
                raise RuntimeError("test: crash after dispatch before RESULT")
            if before_store_commit is not None:
                before_store_commit(receipt)
            if self.crash_after_result_before_local:
                raise RuntimeError("test: crash after RESULT before local commit")

        _state, _result, _error, execution_receipt, _created = self.store.execute_once(
            operation_id=op, binding_digest=binding_digest,
            binding=dict(getattr(pending_execution, "binding")),
            execute=do_dispatch, make_receipt=make_receipt, now=1_800_000_000,
            con=store_con, before_commit=before_commit,
        )
        return execution_receipt


def _caller() -> CallerIdentity:
    return CallerIdentity(
        sid="S-1-5-99-TEST", account="TESTHOST\\exec_acct",
        via="TEST_SIMULATED", is_os_backed=False,
    )


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.dir = Path(tempfile.mkdtemp(prefix="e1c-"))
        self.addCleanup(lambda: shutil.rmtree(self.dir, ignore_errors=True))
        self.exec_key = Ed25519PrivateKey.generate()
        self.journal_key = Ed25519PrivateKey.generate()
        self.config, self.raw = make_config(
            base_dir=self.dir, journal_key=self.journal_key, executor_key=self.exec_key,
            executor_id=EXEC_ID, os_identity=_caller().account, pipe_name=f"e1c-{os.getpid()}",
        )
        self.service = JournalService(self.config, require_os_backed=False)
        self.service.start()
        self.addCleanup(self.service.stop)
        self.channel = InProcessChannel(self.service, _caller())
        self.client = JournalClient(self.channel, executor_id=EXEC_ID)
        # A1: state and store share ONE database file.
        db = self.dir / "exec-store.sqlite3"
        self.store = ExecutionStore(db)
        self.state = E1CLocalState(db)
        self.gate = _StubGateExecutor(key=self.exec_key, store=self.store)
        self.orch = JournalBackedExecutor(
            executor=self.gate, client=self.client, store=self.store, state=self.state,
            executor_public_key=self.exec_key.public_key(),
        )

    def _op(self, oid: str = "op-c-1") -> _Pending:
        return _Pending(oid)

    def _seed_result_in_journal(self, op: _Pending):
        receipt = receipt_v2(
            executor_id=EXEC_ID, operation_id=op.operation_id,
            binding_digest=op.binding_digest, result=RESULT, key=self.exec_key,
        )
        self.client.append_intent(operation_id=op.operation_id, binding_digest=op.binding_digest)
        self.client.append_result(
            operation_id=op.operation_id, binding_digest=op.binding_digest,
            result_value=RESULT, execution_receipt=receipt,
        )
        return receipt


class C1IPCClientTests(unittest.TestCase):
    """C1: typed client maps the API envelope exactly, fail-closed."""

    def test_I01_client_rejects_error_response(self):
        class Bad:
            def call(self, method, params):
                return {"ok": False, "error": {"code": "EXECUTOR_ID_MISMATCH", "message": "no"}}
        client = JournalClient(Bad(), executor_id=EXEC_ID)
        with self.assertRaises(JournalClientError) as ctx:
            client.append_intent(operation_id="op", binding_digest="sha256:" + "b" * 64)
        self.assertEqual(ctx.exception.code, "EXECUTOR_ID_MISMATCH")

    def test_I02_client_rejects_malformed_response(self):
        class Bad:
            def call(self, method, params):
                return {"unexpected": True}
        client = JournalClient(Bad(), executor_id=EXEC_ID)
        with self.assertRaises(JournalClientError) as ctx:
            client.verify_integrity()
        self.assertEqual(ctx.exception.code, "BAD_RESPONSE")


class C2ExecutionChainTests(_Base):
    """C1/C2: RESULT before local commit, INTENT before dispatch, bound original."""

    def test_E01_full_chain_success_and_dispatch_once(self):
        op = self._op()
        receipt = self.orch.execute_with_journal(
            pending_execution=op, operation_id=op.operation_id,
            binding_digest=op.binding_digest, dispatch_args={},
        )
        self.assertEqual(self.gate.dispatch_count, 1)
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        intent = self.client.get_entry(operation_id=op.operation_id, phase="INTENT")
        result = self.client.get_entry(operation_id=op.operation_id, phase="RESULT")
        self.assertIsNotNone(intent)
        self.assertIsNotNone(result)
        self.assertLess(intent["seq"], result["seq"])
        self.assertEqual(result["envelope"]["execution_receipt"], receipt)
        self.assertEqual(result["envelope"]["result"], RESULT)
        self.assertEqual(self.store.get_receipt(op.operation_id), receipt)

    def test_E02_retry_returns_original_receipt_no_second_dispatch(self):
        op = self._op()
        first = self.orch.execute_with_journal(
            pending_execution=op, operation_id=op.operation_id,
            binding_digest=op.binding_digest, dispatch_args={},
        )
        second = self.orch.execute_with_journal(
            pending_execution=op, operation_id=op.operation_id,
            binding_digest=op.binding_digest, dispatch_args={},
        )
        self.assertEqual(first, second)
        self.assertEqual(self.gate.dispatch_count, 1)

    def test_E03_gate_refusal_still_records_intent_then_no_result(self):
        op = self._op("op-c-fail")
        self.gate.fail_gate = True
        with self.assertRaises(RuntimeError):
            self.orch.execute_with_journal(
                pending_execution=op, operation_id=op.operation_id,
                binding_digest=op.binding_digest, dispatch_args={},
            )
        self.assertIsNotNone(self.client.get_entry(operation_id=op.operation_id, phase="INTENT"))
        self.assertIsNone(self.client.get_entry(operation_id=op.operation_id, phase="RESULT"))
        self.assertIsNone(self.store.get_receipt(op.operation_id))

    def test_E04_binding_conflict_is_fail_closed(self):
        op = self._op()
        self.orch.execute_with_journal(
            pending_execution=op, operation_id=op.operation_id,
            binding_digest=op.binding_digest, dispatch_args={},
        )
        with self.assertRaises(E1CFailClosed) as ctx:
            self.orch.execute_with_journal(
                pending_execution=op, operation_id=op.operation_id,
                binding_digest="sha256:" + "c" * 64, dispatch_args={},
            )
        self.assertEqual(ctx.exception.code, "REQUEST_BINDING_MISMATCH")
        self.assertEqual(self.gate.dispatch_count, 1)


class C3RecoveryTests(_Base):
    """C3: RESULT-in-Journal recovery without re-dispatch or re-signing."""

    def test_R01_result_in_journal_local_behind_recovers_original_receipt(self):
        op = self._op("op-c-rec")
        original = self._seed_result_in_journal(op)
        db2 = self.dir / "exec-store-2.sqlite3"
        store2 = ExecutionStore(db2)
        state2 = E1CLocalState(db2)
        orch2 = JournalBackedExecutor(
            executor=self.gate, client=self.client, store=store2, state=state2,
            executor_public_key=self.exec_key.public_key(),
        )
        recovered = orch2.execute_with_journal(
            pending_execution=op, operation_id=op.operation_id,
            binding_digest=op.binding_digest, dispatch_args={},
        )
        self.assertEqual(recovered, original)
        self.assertEqual(self.gate.dispatch_count, 0)
        with state2._db() as con:
            self.assertEqual(state2.get_status(con, op.operation_id)["receipt"], original)
        self.assertEqual(store2.get_receipt(op.operation_id), original)

    def test_R02_recovered_receipt_tampered_is_rejected(self):
        op = self._op("op-c-tamper")
        self._seed_result_in_journal(op)
        env = result_envelope(
            operation_id=op.operation_id, binding_digest=op.binding_digest,
            result={"value": 999}, receipt=receipt_v2(
                executor_id=EXEC_ID, operation_id=op.operation_id,
                binding_digest=op.binding_digest, result=RESULT, key=self.exec_key,
            ),
        )
        from online_budget.e1_encoding import canonical_digest
        fake_entry = {
            "phase": "RESULT", "operation_id": op.operation_id, "envelope": env,
            "payload_digest": canonical_digest("e1-result-envelope-v1", env),
        }
        with self.assertRaises(E1CReceiptInvalid):
            recover_result_from_entry(
                entry=fake_entry, operation_id=op.operation_id,
                binding_digest=op.binding_digest,
                executor_public_key=self.exec_key.public_key(),
            )

    def test_R03_g2_diverged_fails_closed(self):
        self._seed_result_in_journal(self._op("op-c-seed"))
        db2 = self.dir / "exec-diverged.sqlite3"
        store2 = ExecutionStore(db2)
        state2 = E1CLocalState(db2)
        with state2.write_lock() as con:
            state2.set_sync(con, last_applied_seq=1, last_checkpoint_digest="sha256:" + "f" * 64)
        orch2 = JournalBackedExecutor(
            executor=self.gate, client=self.client, store=store2, state=state2,
            executor_public_key=self.exec_key.public_key(),
        )
        newop = self._op("op-c-new")
        with self.assertRaises(E1CStateDiverged):
            orch2.execute_with_journal(
                pending_execution=newop, operation_id=newop.operation_id,
                binding_digest=newop.binding_digest, dispatch_args={},
            )
        self.assertEqual(self.gate.dispatch_count, 0)

    def test_R04_rollback_suspected_fails_closed(self):
        self._seed_result_in_journal(self._op("op-c-seed2"))
        head = self.client.get_head()
        db2 = self.dir / "exec-suspected.sqlite3"
        store2 = ExecutionStore(db2)
        state2 = E1CLocalState(db2)
        with state2.write_lock() as con:
            state2.set_sync(con, last_applied_seq=int(head["seq"]) + 5,
                            last_checkpoint_digest="sha256:" + "a" * 64)
        orch2 = JournalBackedExecutor(
            executor=self.gate, client=self.client, store=store2, state=state2,
            executor_public_key=self.exec_key.public_key(),
        )
        newop = self._op("op-c-new2")
        with self.assertRaises(E1CRollbackSuspected):
            orch2.execute_with_journal(
                pending_execution=newop, operation_id=newop.operation_id,
                binding_digest=newop.binding_digest, dispatch_args={},
            )
        self.assertEqual(self.gate.dispatch_count, 0)

    def test_R05_journal_integrity_failure_fails_closed(self):
        class BadVerify:
            def __init__(self, real):
                self.real = real
            def call(self, method, params):
                if method == "verify_integrity":
                    return {"ok": False, "error": {"code": "INTEGRITY_FAILURE", "message": "tampered"}}
                return self.real.call(method, params)
        bad_client = JournalClient(BadVerify(self.channel), executor_id=EXEC_ID)
        orch = JournalBackedExecutor(
            executor=self.gate, client=bad_client, store=self.store, state=self.state,
            executor_public_key=self.exec_key.public_key(),
        )
        op = self._op("op-c-int")
        with self.assertRaises(E1CIntegrityFailure):
            orch.execute_with_journal(
                pending_execution=op, operation_id=op.operation_id,
                binding_digest=op.binding_digest, dispatch_args={},
            )
        self.assertEqual(self.gate.dispatch_count, 0)

    def test_R06_receipt_validation_failure_refuses_result(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        wrong_key = Ed25519PrivateKey.generate()
        db2 = self.dir / "exec-badsig.sqlite3"
        store2 = ExecutionStore(db2)
        bad_gate = _StubGateExecutor(key=wrong_key, store=store2)
        orch = JournalBackedExecutor(
            executor=bad_gate, client=self.client, store=store2,
            executor_public_key=self.exec_key.public_key(),
        )
        op = self._op("op-c-badsig")
        with self.assertRaises(E1CFailClosed) as ctx:
            orch.execute_with_journal(
                pending_execution=op, operation_id=op.operation_id,
                binding_digest=op.binding_digest, dispatch_args={},
            )
        self.assertIn("RESULT_", ctx.exception.code)
        self.assertIsNone(self.client.get_entry(operation_id=op.operation_id, phase="RESULT"))

    def test_R07_g2_behind_is_not_rollback(self):
        self._seed_result_in_journal(self._op("op-c-a"))
        self._seed_result_in_journal(self._op("op-c-b"))
        cp1 = self.client.get_checkpoint(seq=1)
        head = self.client.get_head()
        self.assertGreater(int(head["seq"]), 1)
        self.assertEqual(
            judge_g2_state(self.client, 1, cp1["checkpoint_digest"]), "LOCAL_STATE_BEHIND"
        )
        self.assertEqual(
            judge_g2_state(self.client, 1, "sha256:" + "d" * 64), "LOCAL_STATE_DIVERGED"
        )


class C4IdentityBindingTests(_Base):
    """C4: request identity re-derived from pending binding before INTENT."""

    def test_B01_operation_id_mismatch_rejected(self):
        op = self._op("op-c-b01")
        with self.assertRaises(E1CFailClosed) as ctx:
            self.orch.execute_with_journal(
                pending_execution=op, operation_id="op-c-OTHER",
                binding_digest=op.binding_digest, dispatch_args={},
            )
        self.assertEqual(ctx.exception.code, "REQUEST_OPERATION_MISMATCH")
        self.assertIsNone(self.client.get_entry(operation_id="op-c-b01", phase="INTENT"))
        self.assertEqual(self.gate.dispatch_count, 0)

    def test_B02_binding_digest_mismatch_rejected(self):
        op = self._op("op-c-b02")
        with self.assertRaises(E1CFailClosed) as ctx:
            self.orch.execute_with_journal(
                pending_execution=op, operation_id=op.operation_id,
                binding_digest="sha256:" + "9" * 64, dispatch_args={},
            )
        self.assertEqual(ctx.exception.code, "REQUEST_BINDING_MISMATCH")
        self.assertIsNone(self.client.get_entry(operation_id="op-c-b02", phase="INTENT"))
        self.assertEqual(self.gate.dispatch_count, 0)

    def test_B03_pending_binding_missing_or_malformed_rejected(self):
        from types import SimpleNamespace
        bad_missing = SimpleNamespace(operation_id="op-c-b03")
        with self.assertRaises(E1CFailClosed) as ctx:
            self.orch.execute_with_journal(
                pending_execution=bad_missing, operation_id="op-c-b03",
                binding_digest="sha256:" + "1" * 64, dispatch_args={},
            )
        self.assertEqual(ctx.exception.code, "BAD_PENDING_BINDING")
        bad_shape = SimpleNamespace(operation_id="op-c-b03b", binding={"operation_id": "op-c-b03b"})
        with self.assertRaises(E1CFailClosed) as ctx:
            self.orch.execute_with_journal(
                pending_execution=bad_shape, operation_id="op-c-b03b",
                binding_digest="sha256:" + "1" * 64, dispatch_args={},
            )
        self.assertEqual(ctx.exception.code, "BAD_PENDING_BINDING")
        self.assertEqual(self.gate.dispatch_count, 0)

    def test_B04_embedded_binding_digest_claim_is_ignored(self):
        op = self._op("op-c-b04")
        op.binding = {**op.binding, "binding_digest": "sha256:" + "0" * 64}
        with self.assertRaises(E1CFailClosed):
            derive_request_identity(op)


class C1CrashWindowTests(_Base):
    """E1.9-C.1 §4 windows 1-4: every recovery records all four artifacts."""

    def _state_of(self, op_id):
        store_row = self.store.get_receipt(op_id)
        intent = self.client.get_entry(operation_id=op_id, phase="INTENT")
        result = self.client.get_entry(operation_id=op_id, phase="RESULT")
        return store_row, intent, result, self.gate.dispatch_count

    def test_W01_intent_written_dispatch_not_run(self):
        op = self._op("op-c-w1")
        self.gate.fail_gate = True
        with self.assertRaises(RuntimeError):
            self.orch.execute_with_journal(
                pending_execution=op, operation_id=op.operation_id,
                binding_digest=op.binding_digest, dispatch_args={},
            )
        store_row, intent, result, dispatched = self._state_of(op.operation_id)
        self.assertIsNone(store_row)
        self.assertIsNotNone(intent)
        self.assertIsNone(result)
        self.assertEqual(dispatched, 0)

    def test_W02_dispatch_done_result_not_written(self):
        op = self._op("op-c-w2")
        self.gate.crash_after_dispatch_before_result = True
        with self.assertRaises(RuntimeError):
            self.orch.execute_with_journal(
                pending_execution=op, operation_id=op.operation_id,
                binding_digest=op.binding_digest, dispatch_args={},
            )
        store_row, intent, result, dispatched = self._state_of(op.operation_id)
        self.assertIsNone(store_row)
        self.assertIsNotNone(intent)
        self.assertIsNone(result)
        self.assertEqual(dispatched, 1)

    def test_W03_result_written_local_commit_not_done_then_retry_recovers(self):
        op = self._op("op-c-w3")
        self.gate.crash_after_result_before_local = True
        with self.assertRaises(RuntimeError):
            self.orch.execute_with_journal(
                pending_execution=op, operation_id=op.operation_id,
                binding_digest=op.binding_digest, dispatch_args={},
            )
        store_row, intent, result, dispatched = self._state_of(op.operation_id)
        self.assertIsNone(store_row)
        self.assertIsNotNone(intent)
        self.assertIsNotNone(result)
        self.assertEqual(dispatched, 1)
        self.gate.crash_after_result_before_local = False
        recovered = self.orch.execute_with_journal(
            pending_execution=op, operation_id=op.operation_id,
            binding_digest=op.binding_digest, dispatch_args={},
        )
        original = result["envelope"]["execution_receipt"]
        self.assertEqual(recovered, original)
        self.assertEqual(self.gate.dispatch_count, 1)
        self.assertEqual(self.store.get_receipt(op.operation_id), original)

    def test_W04_local_commit_failure_retry_recovers(self):
        op = self._op("op-c-w4")
        self.gate.crash_after_result_before_local = True
        with self.assertRaises(RuntimeError):
            self.orch.execute_with_journal(
                pending_execution=op, operation_id=op.operation_id,
                binding_digest=op.binding_digest, dispatch_args={},
            )
        self.gate.crash_after_result_before_local = False
        first = self.orch.execute_with_journal(
            pending_execution=op, operation_id=op.operation_id,
            binding_digest=op.binding_digest, dispatch_args={},
        )
        second = self.orch.execute_with_journal(
            pending_execution=op, operation_id=op.operation_id,
            binding_digest=op.binding_digest, dispatch_args={},
        )
        self.assertEqual(first, second)
        self.assertEqual(self.gate.dispatch_count, 1)

    def test_W05_behind_multi_entry_replay_recovers_originals(self):
        ops = [self._op(f"op-c-rp-{i}") for i in range(3)]
        originals = [self._seed_result_in_journal(o) for o in ops]
        db2 = self.dir / "exec-replay.sqlite3"
        store2 = ExecutionStore(db2)
        state2 = E1CLocalState(db2)
        gate2 = _StubGateExecutor(key=self.exec_key, store=store2)
        orch2 = JournalBackedExecutor(
            executor=gate2, client=self.client, store=store2, state=state2,
            executor_public_key=self.exec_key.public_key(),
        )
        with state2.write_lock() as con:
            cp1 = self.client.get_checkpoint(seq=1)
            state2.set_sync(con, last_applied_seq=1, last_checkpoint_digest=cp1["checkpoint_digest"])
        newop = self._op("op-c-rp-new")
        orch2.execute_with_journal(
            pending_execution=newop, operation_id=newop.operation_id,
            binding_digest=newop.binding_digest, dispatch_args={},
        )
        # BEHIND replay restores ORIGINAL receipts into the local sync state
        # (E1CLocalState), which is what drives local idempotency.  It does NOT
        # fabricate ExecutionStore rows for ops executed by another Executor.
        with state2._db() as con:
            for i, o in enumerate(ops[1:], start=1):
                st = state2.get_status(con, o.operation_id)
                self.assertIsNotNone(st)
                self.assertEqual(st["receipt"], originals[i])
        self.assertEqual(gate2.dispatch_count, 1)

    def test_W06_behind_replay_bad_digest_fails_closed(self):
        ops = [self._op(f"op-c-bad-{i}") for i in range(2)]
        for o in ops:
            self._seed_result_in_journal(o)
        real_channel = self.channel

        class BadReplay:
            def __init__(self, real):
                self.real = real
            def call(self, method, params):
                resp = self.real.call(method, params)
                if method == "get_entries_from" and resp.get("ok"):
                    entries = [dict(e) for e in resp["result"]["entries"]]
                    for e in entries:
                        e["prev_digest"] = "sha256:" + "0" * 64
                    resp = {"ok": True, "result": {"entries": entries}}
                return resp

        bad_client = JournalClient(BadReplay(real_channel), executor_id=EXEC_ID)
        db2 = self.dir / "exec-badreplay.sqlite3"
        store2 = ExecutionStore(db2)
        state2 = E1CLocalState(db2)
        with state2.write_lock() as con:
            cp1 = bad_client.get_checkpoint(seq=1)
            state2.set_sync(con, last_applied_seq=1, last_checkpoint_digest=cp1["checkpoint_digest"])
        gate2 = _StubGateExecutor(key=self.exec_key, store=store2)
        orch2 = JournalBackedExecutor(
            executor=gate2, client=bad_client, store=store2, state=state2,
            executor_public_key=self.exec_key.public_key(),
        )
        newop = self._op("op-c-bad-new")
        with self.assertRaises(E1CStateDiverged):
            orch2.execute_with_journal(
                pending_execution=newop, operation_id=newop.operation_id,
                binding_digest=newop.binding_digest, dispatch_args={},
            )
        self.assertEqual(gate2.dispatch_count, 0)

    def test_W07_no_dispatch_while_behind_incomplete(self):
        self._seed_result_in_journal(self._op("op-c-bh-seed"))
        real_channel = self.channel

        class TruncatedReplay:
            def __init__(self, real):
                self.real = real
            def call(self, method, params):
                resp = self.real.call(method, params)
                if method == "get_entries_from" and resp.get("ok"):
                    resp = {"ok": True, "result": {"entries": []}}
                return resp

        bad_client = JournalClient(TruncatedReplay(real_channel), executor_id=EXEC_ID)
        db2 = self.dir / "exec-trunc.sqlite3"
        store2 = ExecutionStore(db2)
        state2 = E1CLocalState(db2)
        with state2.write_lock() as con:
            cp1 = self.client.get_checkpoint(seq=1)
            state2.set_sync(con, last_applied_seq=1, last_checkpoint_digest=cp1["checkpoint_digest"])
        gate2 = _StubGateExecutor(key=self.exec_key, store=store2)
        orch2 = JournalBackedExecutor(
            executor=gate2, client=bad_client, store=store2, state=state2,
            executor_public_key=self.exec_key.public_key(),
        )
        newop = self._op("op-c-bh-new")
        with self.assertRaises(E1CStateDiverged):
            orch2.execute_with_journal(
                pending_execution=newop, operation_id=newop.operation_id,
                binding_digest=newop.binding_digest, dispatch_args={},
            )
        self.assertEqual(gate2.dispatch_count, 0)

    def test_W08_a1_lock_serializes_two_executors_shared_store(self):
        op = self._op("op-c-a1")
        other_gate = _StubGateExecutor(key=self.exec_key, store=self.store)
        orch2 = JournalBackedExecutor(
            executor=other_gate, client=self.client, store=self.store, state=self.state,
            executor_public_key=self.exec_key.public_key(),
        )
        results: list = []
        barrier = threading.Barrier(2)

        def run(o):
            barrier.wait(timeout=10)
            try:
                results.append(("ok", o.execute_with_journal(
                    pending_execution=op, operation_id=op.operation_id,
                    binding_digest=op.binding_digest, dispatch_args={},
                )))
            except Exception as exc:
                results.append(("err", exc))

        threads = [threading.Thread(target=run, args=(o,)) for o in (self.orch, orch2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertTrue(all(kind == "ok" for kind, _ in results), results)
        self.assertEqual(results[0][1], results[1][1])
        self.assertEqual(self.gate.dispatch_count + other_gate.dispatch_count, 1)
        self.assertIsNotNone(self.store.get_receipt(op.operation_id))


class C4ConcurrencyTests(_Base):
    """C4: shared A1 store concurrency -> dispatch once."""

    def test_X01_two_threads_same_operation_single_dispatch(self):
        op = self._op("op-c-concurrent")
        results: list = []
        barrier = threading.Barrier(2)

        def worker():
            barrier.wait(timeout=10)
            try:
                r = self.orch.execute_with_journal(
                    pending_execution=op, operation_id=op.operation_id,
                    binding_digest=op.binding_digest, dispatch_args={},
                )
                results.append(("ok", r))
            except Exception as exc:
                results.append(("err", exc))

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(self.gate.dispatch_count, 1)
        self.assertTrue(all(kind == "ok" for kind, _ in results), results)
        self.assertEqual(results[0][1], results[1][1])


@unittest.skipUnless(os.environ.get("E1C_REAL_IPC") == "1", "set E1C_REAL_IPC=1 for real pipe test")
class C4RealProcessTests(unittest.TestCase):
    """Real cross-process IPC with OS-backed identity (environment-gated)."""

    def test_P01_standalone_journal_process_full_chain(self):
        import uuid
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from online_budget.journal_identity import current_process_identity

        d = Path(tempfile.mkdtemp(prefix="e1c-proc-"))
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        exec_key = Ed25519PrivateKey.generate()
        journal_key = Ed25519PrivateKey.generate()
        ident = current_process_identity()
        pipe = f"e1c-proc-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        config, raw = make_config(
            base_dir=d, journal_key=journal_key, executor_key=exec_key,
            executor_id=EXEC_ID, os_identity=ident.account, pipe_name=pipe,
            allowed_sid=ident.sid,
        )
        cfg_path = d / "service.json"
        write_service_config_json(cfg_path, raw)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src") + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.Popen(
            [sys.executable, "-m", "online_budget.journal_service_main", "--config", str(cfg_path)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        def _cleanup_proc(p):
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=10)
            for stream in (p.stdout, p.stderr):
                if stream is not None:
                    stream.close()
        self.addCleanup(_cleanup_proc, proc)

        client = JournalClient(NamedPipeClient(pipe, connect_retries=200), executor_id=EXEC_ID)
        self.assertEqual(client.verify_integrity(), 0)
        db = d / "exec-store.sqlite3"
        store = ExecutionStore(db)
        state = E1CLocalState(db)
        gate = _StubGateExecutor(key=exec_key, store=store)
        orch = JournalBackedExecutor(
            executor=gate, client=client, store=store, state=state,
            executor_public_key=exec_key.public_key(),
        )
        op = _Pending("op-c-proc")
        receipt = orch.execute_with_journal(
            pending_execution=op, operation_id=op.operation_id,
            binding_digest=op.binding_digest, dispatch_args={},
        )
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        self.assertEqual(gate.dispatch_count, 1)
        proc.terminate(); proc.wait(timeout=10)
        proc2 = subprocess.Popen(
            [sys.executable, "-m", "online_budget.journal_service_main", "--config", str(cfg_path)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.addCleanup(_cleanup_proc, proc2)
        db2 = d / "exec-store-2.sqlite3"
        store2 = ExecutionStore(db2)
        state2 = E1CLocalState(db2)
        orch2 = JournalBackedExecutor(
            executor=gate, client=client, store=store2, state=state2,
            executor_public_key=exec_key.public_key(),
        )
        recovered = orch2.execute_with_journal(
            pending_execution=op, operation_id=op.operation_id,
            binding_digest=op.binding_digest, dispatch_args={},
        )
        self.assertEqual(recovered, receipt)
        self.assertEqual(gate.dispatch_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
