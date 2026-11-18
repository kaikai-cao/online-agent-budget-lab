"""E1.9-C system integration tests (Journal Service <-> Executor chain).

Layers, kept strictly separate (E1.9-C task §4):
  * In-process orchestration tests: a stub executor stands in for the frozen
    four-gate chain, with a REAL E1.9-B JournalService behind InProcessChannel.
    These prove C1/C2/C3 orchestration, idempotency, recovery, G2 three-state and
    fail-closed deterministically and fast.  InProcessChannel is TEST-ONLY and
    is never a production identity boundary (E0 §9.3).
  * Environment-gated REAL Named Pipe + standalone process test
    (E1C_REAL_IPC=1): proves cross-process IPC with OS-backed identity and the
    exact same JournalBackedExecutor orchestration object.  Single-process
    results are NEVER used to claim cross-process behaviour.

Honest boundary: Journal is a trusted recorder, not an execution-proof oracle.
Recovery returns the original signed Receipt; no re-signing.  No G1b / exactly-
once / execution-truth claim.  These tests are not a formal security proof.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, Mapping
from unittest import mock

from online_budget import execution_receipts as er
from online_budget.canonical import digest
from online_budget.journal_backed_executor import (
    E1CFailClosed,
    E1CIntegrityFailure,
    E1CReceiptInvalid,
    E1CRollbackSuspected,
    E1CStateDiverged,
    E1CLocalState,
    JournalBackedExecutor,
    judge_g2_state,
    recover_result_from_entry,
)
from online_budget.journal_client import JournalClient, JournalClientError
from online_budget.journal_identity import CallerIdentity
from online_budget.journal_ipc import InProcessChannel, NamedPipeClient
from online_budget.journal_service import JournalService
from online_budget.journal_service_config import ServiceConfig

from _e1b_helpers import make_config, receipt_v2, result_envelope, write_service_config_json

EXEC_ID = "exec-c"
BINDING = "sha256:" + "b" * 64
RESULT = {"value": 42, "echo": "ok"}


class _StubGateExecutor:
    """Stands in for TrustedToolExecutor.execute_e1's four-gate+dispatch+seal.

    It returns a REAL Receipt v2 signed by the same executor key registered in
    the Journal Service, and counts dispatches so recovery/no-replay is testable.
    The frozen executor itself is not modified.
    """

    def __init__(self, *, key, executor_id: str = EXEC_ID, binding_digest: str = BINDING) -> None:
        self.key = key
        self.executor_id = executor_id
        self.binding_digest = binding_digest
        self.dispatch_count = 0
        self.fail_gate = False

    def execute_e1(self, *, pending_execution: Any, **kwargs) -> dict[str, Any]:
        if self.fail_gate:
            raise RuntimeError("test: final gate refused")
        if isinstance(pending_execution, Mapping):
            op = pending_execution["operation_id"]
        else:
            op = getattr(pending_execution, "operation_id")
        self.dispatch_count += 1
        return receipt_v2(
            executor_id=self.executor_id, operation_id=op,
            binding_digest=self.binding_digest, result=RESULT, key=self.key,
        )


class _Pending:
    def __init__(self, operation_id: str) -> None:
        self.operation_id = operation_id


def _caller() -> CallerIdentity:
    return CallerIdentity(
        sid="S-1-5-99-TEST", account="TESTHOST\\exec_acct",
        via="TEST_SIMULATED", is_os_backed=False,
    )


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.dir = Path(tempfile.mkdtemp(prefix="e1c-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))
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
        self.state = E1CLocalState(self.dir / "e1c-local.sqlite3")
        self.gate = _StubGateExecutor(key=self.exec_key)
        self.orch = JournalBackedExecutor(
            executor=self.gate, client=self.client, state=self.state,
            executor_public_key=self.exec_key.public_key(),
        )

    def _op(self, oid: str = "op-c-1") -> _Pending:
        return _Pending(oid)


class C1IPCClientTests(unittest.TestCase):
    """C1: typed client maps the six-API envelope exactly, fail-closed."""

    def test_I01_client_rejects_error_response(self):
        class Bad:
            def call(self, method, params):
                return {"ok": False, "error": {"code": "EXECUTOR_ID_MISMATCH", "message": "no"}}
        client = JournalClient(Bad(), executor_id=EXEC_ID)
        with self.assertRaises(JournalClientError) as ctx:
            client.append_intent(operation_id="op", binding_digest=BINDING)
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
    """C2: INTENT before dispatch, RESULT bound to original receipt."""

    def test_E01_full_chain_success_and_dispatch_once(self):
        receipt = self.orch.execute_with_journal(
            pending_execution=self._op(), operation_id="op-c-1",
            binding_digest=BINDING, dispatch_args={},
        )
        self.assertEqual(self.gate.dispatch_count, 1)
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        # Journal has both phases, in order.
        intent = self.client.get_entry(operation_id="op-c-1", phase="INTENT")
        result = self.client.get_entry(operation_id="op-c-1", phase="RESULT")
        self.assertIsNotNone(intent)
        self.assertIsNotNone(result)
        self.assertLess(intent["seq"], result["seq"])
        # RESULT envelope binds the exact original receipt.
        self.assertEqual(result["envelope"]["execution_receipt"], receipt)
        self.assertEqual(result["envelope"]["result"], RESULT)

    def test_E02_retry_returns_original_receipt_no_second_dispatch(self):
        first = self.orch.execute_with_journal(
            pending_execution=self._op(), operation_id="op-c-1",
            binding_digest=BINDING, dispatch_args={},
        )
        second = self.orch.execute_with_journal(
            pending_execution=self._op(), operation_id="op-c-1",
            binding_digest=BINDING, dispatch_args={},
        )
        self.assertEqual(first, second)
        self.assertEqual(self.gate.dispatch_count, 1)

    def test_E03_gate_refusal_still_records_intent_then_no_result(self):
        self.gate.fail_gate = True
        with self.assertRaises(RuntimeError):
            self.orch.execute_with_journal(
                pending_execution=self._op("op-c-fail"), operation_id="op-c-fail",
                binding_digest=BINDING, dispatch_args={},
            )
        # INTENT was written before dispatch; no RESULT; G1b not claimed.
        self.assertIsNotNone(self.client.get_entry(operation_id="op-c-fail", phase="INTENT"))
        self.assertIsNone(self.client.get_entry(operation_id="op-c-fail", phase="RESULT"))

    def test_E04_binding_conflict_is_fail_closed(self):
        self.orch.execute_with_journal(
            pending_execution=self._op(), operation_id="op-c-1",
            binding_digest=BINDING, dispatch_args={},
        )
        with self.assertRaises(Exception):
            self.orch.execute_with_journal(
                pending_execution=self._op(), operation_id="op-c-1",
                binding_digest="sha256:" + "c" * 64, dispatch_args={},
            )
        self.assertEqual(self.gate.dispatch_count, 1)


class C3RecoveryTests(_Base):
    """C3: RESULT-in-Journal recovery without re-dispatch or re-signing."""

    def _seed_result_in_journal(self, oid="op-c-rec"):
        receipt = receipt_v2(
            executor_id=EXEC_ID, operation_id=oid,
            binding_digest=BINDING, result=RESULT, key=self.exec_key,
        )
        self.client.append_intent(operation_id=oid, binding_digest=BINDING)
        self.client.append_result(
            operation_id=oid, binding_digest=BINDING,
            result_value=RESULT, execution_receipt=receipt,
        )
        return receipt

    def test_R01_result_in_journal_local_behind_recovers_original_receipt(self):
        oid = "op-c-rec"
        original = self._seed_result_in_journal(oid)
        # Fresh state (simulates local commit lost / new Executor instance).
        state2 = E1CLocalState(self.dir / "e1c-local2.sqlite3")
        orch2 = JournalBackedExecutor(
            executor=self.gate, client=self.client, state=state2,
            executor_public_key=self.exec_key.public_key(),
        )
        recovered = orch2.execute_with_journal(
            pending_execution=self._op(oid), operation_id=oid,
            binding_digest=BINDING, dispatch_args={},
        )
        self.assertEqual(recovered, original)  # byte-identical original
        self.assertEqual(self.gate.dispatch_count, 0)  # no re-dispatch
        with state2._db() as con:
            self.assertEqual(state2.get_status(con, oid)["receipt"], original)

    def test_R02_recovered_receipt_tampered_is_rejected(self):
        oid = "op-c-tamper"
        self._seed_result_in_journal(oid)
        # Corrupt the envelope result inside a synthetic entry and verify the
        # recovery validator rejects it (digest + B-F1 binding check).
        env = result_envelope(
            operation_id=oid, binding_digest=BINDING,
            result={"value": 999}, receipt=receipt_v2(
                executor_id=EXEC_ID, operation_id=oid,
                binding_digest=BINDING, result=RESULT, key=self.exec_key,
            ),
        )
        from online_budget.e1_encoding import canonical_digest
        fake_entry = {
            "phase": "RESULT", "operation_id": oid, "envelope": env,
            "payload_digest": canonical_digest("e1-result-envelope-v1", env),
        }
        with self.assertRaises(E1CReceiptInvalid):
            recover_result_from_entry(
                entry=fake_entry, operation_id=oid, binding_digest=BINDING,
                executor_public_key=self.exec_key.public_key(),
            )

    def test_R03_g2_diverged_fails_closed(self):
        # Fabricate local sync state that claims a checkpoint digest that
        # differs from the authoritative one at the same seq.
        original = self._seed_result_in_journal("op-c-seed")
        with self.state.write_lock() as con:
            self.state.set_sync(con, last_applied_seq=1, last_checkpoint_digest="sha256:" + "f" * 64)
        state2 = E1CLocalState(self.dir / "e1c-diverged.sqlite3")
        with state2.write_lock() as con:
            state2.set_sync(con, last_applied_seq=1, last_checkpoint_digest="sha256:" + "e" * 64)
        orch2 = JournalBackedExecutor(
            executor=self.gate, client=self.client, state=state2,
            executor_public_key=self.exec_key.public_key(),
        )
        with self.assertRaises(E1CStateDiverged):
            orch2.execute_with_journal(
                pending_execution=self._op("op-c-new"), operation_id="op-c-new",
                binding_digest=BINDING, dispatch_args={},
            )
        self.assertEqual(self.gate.dispatch_count, 0)

    def test_R04_rollback_suspected_fails_closed(self):
        self._seed_result_in_journal("op-c-seed2")
        head = self.client.get_head()
        state2 = E1CLocalState(self.dir / "e1c-suspected.sqlite3")
        with state2.write_lock() as con:
            # Local cursor ahead of authority -> no same-seq evidence.
            state2.set_sync(con, last_applied_seq=int(head["seq"]) + 5,
                            last_checkpoint_digest="sha256:" + "a" * 64)
        orch2 = JournalBackedExecutor(
            executor=self.gate, client=self.client, state=state2,
            executor_public_key=self.exec_key.public_key(),
        )
        with self.assertRaises(E1CRollbackSuspected):
            orch2.execute_with_journal(
                pending_execution=self._op("op-c-new2"), operation_id="op-c-new2",
                binding_digest=BINDING, dispatch_args={},
            )
        self.assertEqual(self.gate.dispatch_count, 0)

    def test_R05_journal_integrity_failure_fails_closed(self):
        # Point client at a channel that refuses verify_integrity.
        class BadVerify:
            def __init__(self, real):
                self.real = real
            def call(self, method, params):
                if method == "verify_integrity":
                    return {"ok": False, "error": {"code": "INTEGRITY_FAILURE", "message": "tampered"}}
                return self.real.call(method, params)
        bad_client = JournalClient(BadVerify(self.channel), executor_id=EXEC_ID)
        orch = JournalBackedExecutor(
            executor=self.gate, client=bad_client, state=self.state,
            executor_public_key=self.exec_key.public_key(),
        )
        with self.assertRaises(E1CIntegrityFailure):
            orch.execute_with_journal(
                pending_execution=self._op("op-c-int"), operation_id="op-c-int",
                binding_digest=BINDING, dispatch_args={},
            )
        self.assertEqual(self.gate.dispatch_count, 0)

    def test_R06_receipt_validation_failure_refuses_result(self):
        # Stub executor signs with the WRONG key -> append_result must reject.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        wrong_key = Ed25519PrivateKey.generate()
        bad_gate = _StubGateExecutor(key=wrong_key)
        orch = JournalBackedExecutor(
            executor=bad_gate, client=self.client, state=self.state,
            executor_public_key=self.exec_key.public_key(),
        )
        with self.assertRaises(E1CFailClosed):
            orch.execute_with_journal(
                pending_execution=self._op("op-c-badsig"), operation_id="op-c-badsig",
                binding_digest=BINDING, dispatch_args={},
            )
        self.assertIsNone(self.client.get_entry(operation_id="op-c-badsig", phase="RESULT"))

    def test_R07_g2_behind_is_not_rollback(self):
        # Add two ops, then judge with a local cursor at seq 1 whose checkpoint
        # MATCHES the authoritative same-seq checkpoint while head is higher.
        self._seed_result_in_journal("op-c-a")
        self._seed_result_in_journal("op-c-b")
        cp1 = self.client.get_checkpoint(seq=1)
        head = self.client.get_head()
        self.assertGreater(int(head["seq"]), 1)
        self.assertEqual(
            judge_g2_state(self.client, 1, cp1["checkpoint_digest"]), "LOCAL_STATE_BEHIND"
        )
        # Same seq but a WRONG digest -> DIVERGED, not BEHIND.
        self.assertEqual(
            judge_g2_state(self.client, 1, "sha256:" + "d" * 64), "LOCAL_STATE_DIVERGED"
        )


class C4ConcurrencyTests(_Base):
    """C4: shared sync-DB concurrency -> dispatch once (A1 serialization)."""

    def test_X01_two_threads_same_operation_single_dispatch(self):
        oid = "op-c-concurrent"
        results: list = []
        barrier = threading.Barrier(2)

        def worker():
            barrier.wait(timeout=10)
            try:
                r = self.orch.execute_with_journal(
                    pending_execution=self._op(oid), operation_id=oid,
                    binding_digest=BINDING, dispatch_args={},
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
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        exec_key = Ed25519PrivateKey.generate()
        journal_key = Ed25519PrivateKey.generate()
        ident = current_process_identity()  # real OS identity of this process
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
        state = E1CLocalState(d / "e1c-local.sqlite3")
        gate = _StubGateExecutor(key=exec_key)
        orch = JournalBackedExecutor(
            executor=gate, client=client, state=state,
            executor_public_key=exec_key.public_key(),
        )
        receipt = orch.execute_with_journal(
            pending_execution=_op_real("op-c-proc"), operation_id="op-c-proc",
            binding_digest=BINDING, dispatch_args={},
        )
        self.assertEqual(receipt["payload"]["status"], "SUCCEEDED")
        self.assertEqual(gate.dispatch_count, 1)
        # Restart service; recovery finds original RESULT, no re-dispatch.
        proc.terminate(); proc.wait(timeout=10)
        proc2 = subprocess.Popen(
            [sys.executable, "-m", "online_budget.journal_service_main", "--config", str(cfg_path)],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.addCleanup(_cleanup_proc, proc2)
        state2 = E1CLocalState(d / "e1c-local2.sqlite3")
        orch2 = JournalBackedExecutor(
            executor=gate, client=client, state=state2,
            executor_public_key=exec_key.public_key(),
        )
        recovered = orch2.execute_with_journal(
            pending_execution=_op_real("op-c-proc"), operation_id="op-c-proc",
            binding_digest=BINDING, dispatch_args={},
        )
        self.assertEqual(recovered, receipt)
        self.assertEqual(gate.dispatch_count, 1)  # still one dispatch total


def _op_real(oid):
    from types import SimpleNamespace
    return SimpleNamespace(operation_id=oid)


if __name__ == "__main__":
    unittest.main(verbosity=2)
