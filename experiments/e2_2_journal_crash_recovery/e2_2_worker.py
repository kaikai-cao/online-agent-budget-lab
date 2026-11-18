"""E2.2 Executor Worker — real cross-process Journal chain with test-only crash barriers.

This is a CHILD PROCESS.  It is started by ``run_experiment.py`` with a single
JSON config path as argv[1].  It:

  * builds a REAL JournalClient over a REAL NamedPipeClient (independent Journal
    Service process started by the parent);
  * builds a REAL ExecutionStore + E1CLocalState on the SAME local SQLite file;
  * drives the REAL JournalBackedExecutor.execute_with_journal orchestration;
  * uses a test-only gate stand-in that drives the REAL ExecutionStore
    ``execute_once`` path (A1 store_con + before_store_commit RESULT hook) and
    records the tool side effect into an INDEPENDENT SQLite counter DB;
  * at the configured scenario barrier, writes a marker file (PID + point) and
    waits for a release file.  The parent forcibly kills this process once the
    marker is observed — no Python exception substitutes for the real kill.

Only test-only wrappers are used.  No production file is modified.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.execution_store import ExecutionStore
from online_budget.journal_backed_executor import E1CLocalState, JournalBackedExecutor
from online_budget.journal_client import JournalClient
from online_budget.journal_ipc import NamedPipeClient

from _e1b_helpers import receipt_v2

RESULT = {"value": 42, "echo": "e22-controlled-effect"}
RELEASE_POLL_S = 0.01
RELEASE_TIMEOUT_S = 90.0


def _barrier(point: str, marker_path: str | None, release_path: str | None) -> None:
    """Confirm arrival at the exact injection point, then block until release.

    The parent intentionally never writes the release file; it kills this
    process.  The timeout is a safety net only (a timed-out worker proceeds and
    would then be recorded by the parent as an INVALID trial).
    """
    if not marker_path:
        return
    marker = Path(marker_path)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(
        json.dumps({"point": point, "pid": _pid(), "ts": time.time()}),
        encoding="utf-8",
    )
    if not release_path:
        return
    release = Path(release_path)
    deadline = time.monotonic() + RELEASE_TIMEOUT_S
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(RELEASE_POLL_S)


def _pid() -> int:
    import os
    return os.getpid()


class BarrierChannel:
    """Test-only channel wrapper: fires a barrier AFTER a successful IPC call."""

    def __init__(self, real: Any, scenario: str, marker_path: str | None,
                 release_path: str | None) -> None:
        self._real = real
        self._scenario = scenario
        self._marker = marker_path
        self._release = release_path

    def call(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        resp = self._real.call(method, params)
        if isinstance(resp, Mapping) and resp.get("ok"):
            if self._scenario == "F1" and method == "append_intent":
                _barrier("F1_AFTER_INTENT_BEFORE_DISPATCH", self._marker, self._release)
            elif self._scenario == "F3" and method == "append_result":
                _barrier("F3_AFTER_RESULT_BEFORE_LOCAL_COMMIT", self._marker, self._release)
        return resp


class _Pending:
    """Real 14-field binding payload stand-in (C4 re-derives from .binding)."""

    def __init__(self, operation_id: str, binding: dict[str, Any], binding_digest: str) -> None:
        self.operation_id = operation_id
        self.binding = binding
        self.binding_digest = binding_digest


class ControlledGate:
    """Test stand-in for the four gates; drives the REAL ExecutionStore path.

    ``do_dispatch`` writes the durable effect into the INDEPENDENT counter DB
    (its own committed transaction) before the Receipt is signed and before
    the RESULT hook runs — this is the F2 injection point.
    """

    def __init__(self, *, key: Ed25519PrivateKey, store: ExecutionStore,
                 effect_db: str, scenario: str, marker_path: str | None,
                 release_path: str | None, operation_id: str,
                 executor_id: str) -> None:
        self.key = key
        self.store = store
        self.effect_db = effect_db
        self.scenario = scenario
        self.marker = marker_path
        self.release = release_path
        self.operation_id = operation_id
        self.executor_id = executor_id
        self.dispatch_count = 0

    def _record_effect(self) -> None:
        con = sqlite3.connect(self.effect_db, timeout=30.0)
        try:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "INSERT INTO dispatch_events(operation_id,created_at) VALUES(?,?)",
                (self.operation_id, time.time()),
            )
            con.execute(
                "INSERT INTO effects(operation_id,invoice_id,created_at) VALUES(?,?,?)",
                (self.operation_id, "INV-E22-ATTACK", time.time()),
            )
            con.commit()
        finally:
            con.close()
        self.dispatch_count += 1

    def execute_e1(self, *, pending_execution: Any, store_con=None,
                   before_store_commit=None, **kwargs) -> dict[str, Any]:
        op = self.operation_id
        bd = pending_execution.binding_digest

        def do_dispatch():
            self._record_effect()
            return dict(RESULT)

        def make_receipt(state, result, error, completed_at):
            return receipt_v2(
                executor_id=self.executor_id, operation_id=op,
                binding_digest=bd, result=result, key=self.key, status=state,
            )

        def before_commit(receipt):
            if self.scenario == "F2":
                _barrier("F2_AFTER_DISPATCH_BEFORE_RESULT", self.marker, self.release)
            if before_store_commit is not None:
                before_store_commit(receipt)

        (_state, _result, _err, execution_receipt, _created) = self.store.execute_once(
            operation_id=op, binding_digest=bd,
            binding=dict(pending_execution.binding),
            execute=do_dispatch, make_receipt=make_receipt,
            now=1_800_000_000, con=store_con, before_commit=before_commit,
        )
        return execution_receipt


def _init_effect_db(path: str) -> None:
    con = sqlite3.connect(path, timeout=30.0)
    try:
        con.execute("CREATE TABLE IF NOT EXISTS dispatch_events("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, "
                    "created_at REAL NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS effects("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, "
                    "invoice_id TEXT NOT NULL, created_at REAL NOT NULL)")
        con.commit()
    finally:
        con.close()


def main() -> int:
    cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    scenario = cfg["scenario"]
    mode = cfg["mode"]  # "crash" | "retry"
    executor_id = cfg["executor_id"]
    op = cfg["operation_id"]
    marker = cfg.get("marker_path")
    release = cfg.get("release_path")

    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(cfg["exec_private_b64"]))

    channel = BarrierChannel(
        NamedPipeClient(cfg["pipe_name"], connect_retries=200),
        scenario if mode == "crash" else "RETRY", marker, release,
    )
    client = JournalClient(channel, executor_id=executor_id)

    store_db = cfg["store_db"]
    store = ExecutionStore(store_db)
    state = E1CLocalState(store_db)
    _init_effect_db(cfg["effect_db"])

    gate = ControlledGate(
        key=key, store=store, effect_db=cfg["effect_db"],
        scenario=scenario if mode == "crash" else "RETRY",
        marker_path=marker, release_path=release,
        operation_id=op, executor_id=executor_id,
    )
    orch = JournalBackedExecutor(
        executor=gate, client=client, store=store, state=state,
        executor_public_key=key.public_key(),
    )
    pending = _Pending(op, dict(cfg["binding"]), cfg["binding_digest"])

    receipt = orch.execute_with_journal(
        pending_execution=pending, operation_id=op,
        binding_digest=cfg["binding_digest"], dispatch_args={},
    )

    if mode == "crash" and scenario == "F4":
        _barrier("F4_AFTER_LOCAL_COMMIT_BEFORE_RESPONSE", marker, release)

    out = {"receipt": dict(receipt), "dispatch_count": gate.dispatch_count,
           "operation_id": op, "mode": mode, "scenario": scenario}
    Path(cfg["result_path"]).write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
