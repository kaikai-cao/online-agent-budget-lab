"""E1.7 — Executor execution-idempotency boundary and SQLite rollback.

Research question (frozen scope): with the E1.5 four credential gates unchanged,
is the Executor's LOCAL SQLite state sufficient for execution anti-replay across
instances, restarts and database restore?

This module is an ATTACK-SURFACE EXPERIMENT, not a fix and not a protocol change.
It never touches production code, E0/E1.0 frozen documents, E1.1-E1.6 tests, or
the Rust crate. It reuses the E1.6 real-chain harness (``_SystemHarness``) which
produces a genuine D10+D11 signed ``PendingExecution``; only the final dispatch
stage is exercised here.

Three experiments (all observations are measured, never asserted from intent):

* T01 shared database — two Executor instances, same identity/key, SAME SQLite
  file, concurrent dispatch of one PendingExecution. Expect exactly one tool
  dispatch (SQLite ``BEGIN IMMEDIATE`` serialises the whole execute-in-transaction
  window) and identical receipts.
* T02 independent databases — two Executor instances, same identity/key but
  SEPARATE SQLite files. The E1.5 gates do not consult any cross-Executor store,
  so both dispatch. Both receipts are individually valid and bound correctly —
  showing that "valid+identical receipt" is NOT evidence of a single execution.
* T03 database rollback — snapshot the real SQLite file before execution, run
  once, restore the file bytes, then retry the SAME PendingExecution. Expect a
  second dispatch with a fully valid, indistinguishable receipt and a DB that
  again shows exactly one row: no external monotonic anchor detects the rewind.

Honest boundary: these are deterministic LOCAL tools. A shared-DB win here is a
SQLite transaction property, not a general exactly-once guarantee; an
independent-DB/rollback double dispatch is an observed property of the current
single-store design, not an exploit against an external API. No finding here is
a formal security proof.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
import threading
import traceback
import unittest
from pathlib import Path

from online_budget.canonical import canonical_json_bytes

# Reuse the frozen E1.6 harness — it builds a real D10 Coordinator + real Rust
# e1_service (real Halo2) + E1.5 Executor chain and returns a signed pending.
# ``tests`` is the discovery top-level dir, so sibling import is valid.
from test_e1_system import (  # noqa: E402
    EXE,
    _SystemHarness,
    _CountingRegistry,
    _binding_from_pending,
    _budget_digest,
)


def _exec_db(ex) -> Path:
    return Path(ex.store.path)


def _exec_rows(ex) -> int:
    # Read-only inspection in WAL mode: use a URI connection with immutable=1 so
    # SQLite never creates/holds -wal/-shm sidecars that would block the rollback
    # test from replacing the database file on Windows.
    uri = f"file:{_exec_db(ex).as_posix()}?mode=ro&immutable=1"
    con = sqlite3.connect(uri, uri=True)
    try:
        return con.execute("SELECT COUNT(*) FROM executions").fetchone()[0]
    finally:
        con.close()


def _execute(ex, h: "_SystemHarness", pending, ctx):
    """Run the E1.5 final gate on ``pending`` through executor ``ex``."""
    return ex.execute_e1(
        pending_execution=pending,
        online_lease_grant=h.lease,
        execution_grant=ctx.execution,
        executor_authorization=ctx.authorization,
        metering_policy=h.policy,
        budget_scope=ctx.scope,
    )


@unittest.skipUnless(EXE.exists(), "e1_service binary not built")
class E1ExecutorStateScopeTests(unittest.TestCase):
    """Measured attack surface of Executor-local idempotency state."""

    # ------------------------------------------------------------------ T01 //
    def test_t01_shared_db_two_instances_dispatch_once(self):
        h = _SystemHarness(self)
        pending = h.run(h.op1)

        shared = tempfile.mkdtemp(prefix="e17-shared-")
        self.addCleanup(shutil.rmtree, shared, ignore_errors=True)

        reg_a, reg_b = _CountingRegistry(), _CountingRegistry()
        ex_a = h.executor(registry=reg_a, store_dir=shared)
        ex_b = h.executor(registry=reg_b, store_dir=shared)
        self.assertEqual(_exec_db(ex_a), _exec_db(ex_b), "precondition: shared DB file")

        barrier = threading.Barrier(2)
        results, errors = [], []

        def worker(ex):
            try:
                barrier.wait(timeout=30)
                results.append(_execute(ex, h, pending, h.op1))
            except Exception as exc:  # measured, not swallowed silently
                errors.append(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")

        threads = [threading.Thread(target=worker, args=(ex,)) for ex in (ex_a, ex_b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        self.assertFalse(any(t.is_alive() for t in threads), "worker deadlock")
        self.assertEqual(errors, [], f"unexpected execution errors: {errors!r}")
        self.assertEqual(len(results), 2)

        # Measured outcome: SQLite serialises the whole transaction, so only
        # one instance actually reaches registry.dispatch().
        self.assertEqual(reg_a.dispatch_count + reg_b.dispatch_count, 1)
        self.assertEqual(_exec_rows(ex_a), 1)
        self.assertEqual(_exec_rows(ex_b), 1)

        # Both callers receive an identical, independently verifiable receipt.
        self.assertEqual(canonical_json_bytes(results[0]), canonical_json_bytes(results[1]))
        binding = _binding_from_pending(pending)
        for ex, rcpt in ((ex_a, results[0]), (ex_b, results[1])):
            self.assertTrue(ex.verify_receipt(rcpt, binding=binding))
            self.assertEqual(rcpt["payload"]["status"], "SUCCEEDED")
            self.assertEqual(rcpt["payload"]["receipt_version"], 2)
            self.assertEqual(rcpt["payload"]["budget_receipt_digest"], _budget_digest(pending))

    # ------------------------------------------------------------------ T02 //
    def test_t02_independent_db_two_instances_dispatch_twice(self):
        h = _SystemHarness(self)
        pending = h.run(h.op1)

        db_a = tempfile.mkdtemp(prefix="e17-db-a-")
        db_b = tempfile.mkdtemp(prefix="e17-db-b-")
        self.addCleanup(shutil.rmtree, db_a, ignore_errors=True)
        self.addCleanup(shutil.rmtree, db_b, ignore_errors=True)

        reg_a, reg_b = _CountingRegistry(), _CountingRegistry()
        ex_a = h.executor(registry=reg_a, store_dir=db_a)
        ex_b = h.executor(registry=reg_b, store_dir=db_b)
        self.assertNotEqual(_exec_db(ex_a), _exec_db(ex_b), "precondition: separate DB files")
        self.assertEqual(ex_a.executor_id, ex_b.executor_id, "precondition: same identity")

        barrier = threading.Barrier(2)
        results, errors = [], []

        def worker(ex):
            try:
                barrier.wait(timeout=30)
                results.append(_execute(ex, h, pending, h.op1))
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}")

        threads = [threading.Thread(target=worker, args=(ex,)) for ex in (ex_a, ex_b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)

        self.assertFalse(any(t.is_alive() for t in threads), "worker deadlock")
        self.assertEqual(errors, [], f"unexpected execution errors: {errors!r}")
        self.assertEqual(len(results), 2)

        # Measured outcome: no gate consults cross-Executor state -> both dispatch.
        self.assertEqual(reg_a.dispatch_count, 1)
        self.assertEqual(reg_b.dispatch_count, 1)
        total = reg_a.dispatch_count + reg_b.dispatch_count
        self.assertEqual(total, 2, "independent DBs produced two real tool dispatches")
        self.assertEqual(_exec_rows(ex_a), 1)
        self.assertEqual(_exec_rows(ex_b), 1)

        # Each DB shows a clean single row, and each receipt is valid + bound.
        # The two receipts are byte-identical (deterministic tool + fixed clock),
        # which proves identical receipts cannot attest a single execution.
        binding = _binding_from_pending(pending)
        for ex, rcpt in ((ex_a, results[0]), (ex_b, results[1])):
            self.assertTrue(ex.verify_receipt(rcpt, binding=binding))
            self.assertEqual(rcpt["payload"]["status"], "SUCCEEDED")
            self.assertEqual(rcpt["payload"]["receipt_version"], 2)
            self.assertEqual(rcpt["payload"]["budget_receipt_digest"], _budget_digest(pending))
            self.assertEqual(
                rcpt["payload"]["executor_authorization_digest"],
                h.op1.authorization.authorization_digest,
            )
        self.assertEqual(canonical_json_bytes(results[0]), canonical_json_bytes(results[1]))

    # ------------------------------------------------------------------ T03 //
    def test_t03_db_rollback_replays_dispatch_and_signatures_cannot_detect(self):
        h = _SystemHarness(self)
        pending = h.run(h.op1)

        store = tempfile.mkdtemp(prefix="e17-rollback-")
        self.addCleanup(shutil.rmtree, store, ignore_errors=True)

        reg = _CountingRegistry()
        ex = h.executor(registry=reg, store_dir=store)
        db = _exec_db(ex)
        snapshot = Path(store) / "exec.before.sqlite3"

        # Real snapshot of the SQLite file BEFORE the first execution (schema
        # exists, zero rows). sqlite3.backup gives a consistent WAL-aware copy.
        src = sqlite3.connect(db)
        dst = sqlite3.connect(snapshot)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        chk = sqlite3.connect(snapshot)
        try:
            self.assertEqual(chk.execute("SELECT COUNT(*) FROM executions").fetchone()[0], 0)
        finally:
            chk.close()

        first = _execute(ex, h, pending, h.op1)
        self.assertEqual(reg.dispatch_count, 1)
        self.assertEqual(_exec_rows(ex), 1)
        self.assertEqual(first["payload"]["status"], "SUCCEEDED")

        # Real rollback: drop WAL sidecars and restore the saved file bytes.
        # ExecutionStore reopens a fresh connection per call, so no stale handle.
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(db) + suffix)
            if sidecar.exists():
                sidecar.unlink()
        shutil.copyfile(snapshot, db)
        self.assertEqual(_exec_rows(ex), 0, "precondition: execution row rolled back")

        # Retry the SAME PendingExecution against the rewound DB.
        second = _execute(ex, h, pending, h.op1)
        self.assertEqual(reg.dispatch_count, 2, "rollback caused a second real dispatch")
        self.assertEqual(_exec_rows(ex), 1, "DB again looks like a single clean execution")

        binding = _binding_from_pending(pending)
        # Both receipts are fully valid and byte-identical: the signature and
        # state checks verify self-consistency only, with no external anchor.
        self.assertTrue(ex.verify_receipt(first, binding=binding))
        self.assertTrue(ex.verify_receipt(second, binding=binding))
        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))
        self.assertEqual(second["payload"]["receipt_version"], 2)
        self.assertEqual(second["payload"]["budget_receipt_digest"], _budget_digest(pending))

        # D11 budget state is untouched by the Executor-side rewind: the D11
        # transition was committed once during h.run(pending) and is reused.
        self.assertEqual(h.d11_state(h.op1)["version"], 1)


if __name__ == "__main__":
    unittest.main()
