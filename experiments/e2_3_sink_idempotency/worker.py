"""E2.3 Executor Worker — real cross-process Journal chain + tool-side Sink.

CHILD PROCESS started by run_experiment.py with one JSON config path as argv[1].

  * REAL JournalClient over REAL NamedPipeClient (independent Journal Service).
  * REAL ExecutionStore + E1CLocalState on the SAME local SQLite file (A1).
  * REAL JournalBackedExecutor.execute_with_journal orchestration.
  * Test-only ControlledSinkGate drives the REAL ExecutionStore.execute_once
    path; its do_dispatch() calls the ExternalToolSink (independent SQLite) with
    an idempotency key derived from the trusted binding identity.
  * At the F2 barrier (after Receipt signed, before Journal RESULT append) the
    worker writes a marker {point,pid,ts} and blocks.  The parent FORCIBLY KILLS
    this process — no Python exception substitutes for the real kill.

Retry runs in a FRESH process with mode="retry": no barrier, same operation_id /
idempotency key.  V2 retry passes DIFFERENT arguments to trigger the Sink's
IDEMPOTENCY_KEY_CONFLICT path.

No production file is modified.
"""

from __future__ import annotations

import base64
import json
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
from sink import (
    ExternalToolSink,
    IdempotencyKeyConflict,
    OUTCOME_CONFLICT,
    OUTCOME_DEDUP_HIT,
    OUTCOME_EXECUTED,
    sink_idempotency_key,
)

RESULT = {"value": 42, "echo": "e23-sink-effect"}
RELEASE_POLL_S = 0.01
RELEASE_TIMEOUT_S = 90.0


def _pid() -> int:
    import os
    return os.getpid()


def _barrier(point: str, marker_path: str | None, release_path: str | None) -> None:
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


class _Pending:
    """Real 14-field binding payload stand-in (C4 re-derives from .binding)."""

    def __init__(self, operation_id: str, binding: dict[str, Any], binding_digest: str) -> None:
        self.operation_id = operation_id
        self.binding = binding
        self.binding_digest = binding_digest


class ControlledSinkGate:
    """Test stand-in for the gates; drives REAL ExecutionStore + Sink.

    The idempotency key is derived here (trusted Executor side) from the binding
    identity, and passed to the Sink as INTERNAL metadata — it is NOT added to
    the tool's public arguments and does not alter D10/D11 binding.
    """

    def __init__(self, *, key: Ed25519PrivateKey, store: ExecutionStore,
                 sink_db: str, variant: str, marker_path: str | None,
                 release_path: str | None, operation_id: str,
                 executor_id: str, tool_name: str, tool_schema_hash: str,
                 arguments: dict[str, Any], invoice_id: str) -> None:
        self.key = key
        self.store = store
        self.sink = ExternalToolSink(sink_db)
        self.variant = variant
        self.marker = marker_path
        self.release = release_path
        self.operation_id = operation_id
        self.executor_id = executor_id
        self.tool_name = tool_name
        self.tool_schema_hash = tool_schema_hash
        self.arguments = arguments
        self.invoice_id = invoice_id
        self.idem_key = sink_idempotency_key(
            executor_id=executor_id, operation_id=operation_id,
        )
        self.dispatch_count = 0
        self.sink_outcomes: list[str] = []
        self.conflict_seen = False

    def _do_sink_dispatch(self) -> dict[str, Any]:
        # Internal metadata (key + identity) is passed to the Sink adapter;
        # public tool arguments stay unchanged.
        self.dispatch_count += 1
        response = self.sink.dispatch(
            idempotency_key=self.idem_key,
            operation_id=self.operation_id,
            executor_id=self.executor_id,
            tool_name=self.tool_name,
            tool_schema_hash=self.tool_schema_hash,
            arguments=self.arguments,          # V2 retry sends DIFFERENT args
            result=RESULT,
            invoice_id=self.invoice_id,
            enabled=(self.variant != "V0"),    # V0 = no sink-side idempotency
        )
        self.sink_outcomes.append(response["outcome"])
        if response["outcome"] == OUTCOME_CONFLICT or response["result"] is None:
            # Surface conflict as a tool error so Receipt records it faithfully.
            self.conflict_seen = True
            raise IdempotencyKeyConflict(
                self.idem_key,
                response.get("expected_digest", ""),
                response.get("request_digest", ""),
            )
        return dict(response["result"])

    def execute_e1(self, *, pending_execution: Any, store_con=None,
                   before_store_commit=None, **kwargs) -> dict[str, Any]:
        op = self.operation_id
        bd = pending_execution.binding_digest

        def make_receipt(state, result, error, completed_at):
            return receipt_v2(
                executor_id=self.executor_id, operation_id=op,
                binding_digest=bd, result=result, key=self.key, status=state,
            )

        def before_commit(receipt):
            # F2: Receipt already signed, Journal RESULT not yet appended.
            _barrier("F2_AFTER_DISPATCH_BEFORE_RESULT", self.marker, self.release)
            if before_store_commit is not None:
                before_store_commit(receipt)

        (_state, _result, _err, execution_receipt, _created) = self.store.execute_once(
            operation_id=op, binding_digest=bd,
            binding=dict(pending_execution.binding),
            execute=self._do_sink_dispatch, make_receipt=make_receipt,
            now=1_800_000_000, con=store_con, before_commit=before_commit,
        )
        return execution_receipt


def main() -> int:
    cfg = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    variant = cfg["variant"]
    mode = cfg["mode"]  # "crash" | "retry"
    executor_id = cfg["executor_id"]
    op = cfg["operation_id"]
    marker = cfg.get("marker_path")
    release = cfg.get("release_path")

    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(cfg["exec_private_b64"]))
    channel = NamedPipeClient(cfg["pipe_name"], connect_retries=200)
    client = JournalClient(channel, executor_id=executor_id)

    store_db = cfg["store_db"]
    store = ExecutionStore(store_db)
    state = E1CLocalState(store_db)  # same DB as store (A1)

    args = dict(cfg["arguments"])
    gate = ControlledSinkGate(
        key=key, store=store, sink_db=cfg["sink_db"],
        variant=variant,
        marker_path=marker if mode == "crash" else None,
        release_path=release if mode == "crash" else None,
        operation_id=op, executor_id=executor_id,
        tool_name=cfg["tool_name"], tool_schema_hash=cfg["tool_schema_hash"],
        arguments=args, invoice_id=cfg["invoice_id"],
    )
    orch = JournalBackedExecutor(
        executor=gate, client=client, store=store, state=state,
        executor_public_key=key.public_key(),
    )
    pending = _Pending(op, dict(cfg["binding"]), cfg["binding_digest"])

    error_code = ""
    receipt: dict[str, Any] | None = None
    try:
        receipt = orch.execute_with_journal(
            pending_execution=pending, operation_id=op,
            binding_digest=cfg["binding_digest"], dispatch_args={},
        )
    except IdempotencyKeyConflict:
        error_code = "IDEMPOTENCY_KEY_CONFLICT"

    out = {
        "receipt": dict(receipt) if isinstance(receipt, dict) else None,
        "dispatch_count": gate.dispatch_count,
        "sink_outcomes": gate.sink_outcomes,
        "operation_id": op, "mode": mode, "variant": variant,
        "idempotency_key": gate.idem_key,
        "conflict_seen": gate.conflict_seen,
        "error_code": error_code,
    }
    Path(cfg["result_path"]).write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
