from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable, Mapping

from .canonical import canonical_json_bytes
from .errors import OperationBindingConflict


class ExecutionInProgress(RuntimeError):
    pass


class ExecutionStore:
    """Durable idempotency store for the deterministic local-tool MVP.

    The tool callback runs inside the same SQLite transaction as its result
    record. This is safe only for deterministic local functions with no external
    side effects. Do not use this transaction pattern for network/API tools.
    """

    def __init__(self, database_path: str | Path) -> None:
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute(
                "CREATE TABLE IF NOT EXISTS executions ("
                "operation_id TEXT PRIMARY KEY, binding_digest TEXT NOT NULL, binding_json TEXT NOT NULL, "
                "state TEXT NOT NULL CHECK(state IN ('SUCCEEDED','FAILED')), result_json TEXT NOT NULL, "
                "error_text TEXT, receipt_json TEXT, created_at INTEGER NOT NULL, completed_at INTEGER NOT NULL)"
            )

    def _connect(self):
        con = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("PRAGMA synchronous=FULL")
        return con

    @contextmanager
    def _db(self):
        con = self._connect()
        try:
            yield con
        finally:
            if con.in_transaction:
                con.rollback()
            con.close()

    def execute_once(
        self, *, operation_id: str, binding_digest: str, binding: Mapping[str, Any],
        execute: Callable[[], Any], make_receipt: Callable[[str, Any, str | None, int], Mapping[str, Any]],
        now: int,
    ) -> tuple[str, Any, str | None, dict[str, Any], bool]:
        """Execute once and atomically persist both result and signed receipt.

        The callback must be a deterministic local function without external side
        effects. Receipt construction is kept inside the same transaction so
        concurrent exact retries always observe the same durable receipt.
        """
        binding_json = canonical_json_bytes(dict(binding)).decode("utf-8")
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT * FROM executions WHERE operation_id=?", (operation_id,)).fetchone()
            if row is not None:
                if row["binding_digest"] != binding_digest or row["binding_json"] != binding_json:
                    raise OperationBindingConflict("operation_id is already bound to another ToolCallBinding")
                state = row["state"]
                result = json.loads(row["result_json"])
                error = row["error_text"]
                receipt_json = row["receipt_json"]
                if receipt_json is None:
                    # Recover records written by the earlier D10.1 implementation,
                    # which persisted the result and receipt in separate transactions.
                    completed_at = int(row["completed_at"])
                    receipt = dict(make_receipt(state, result, error, completed_at))
                    encoded_receipt = canonical_json_bytes(receipt).decode("utf-8")
                    con.execute(
                        "UPDATE executions SET receipt_json=? WHERE operation_id=? AND receipt_json IS NULL",
                        (encoded_receipt, operation_id),
                    )
                    receipt_json = encoded_receipt
                con.commit()
                return state, result, error, json.loads(receipt_json), False

            try:
                result = execute()
                result_json = canonical_json_bytes(result).decode("utf-8")
                state, error = "SUCCEEDED", None
            except Exception as exc:  # Persist a stable failure; never rerun the same operation.
                result_json = canonical_json_bytes({"error": type(exc).__name__}).decode("utf-8")
                result = json.loads(result_json)
                state, error = "FAILED", f"{type(exc).__name__}: {exc}"

            receipt = dict(make_receipt(state, result, error, now))
            receipt_json = canonical_json_bytes(receipt).decode("utf-8")
            con.execute(
                "INSERT INTO executions(operation_id,binding_digest,binding_json,state,result_json,error_text,receipt_json,created_at,completed_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (operation_id, binding_digest, binding_json, state, result_json, error, receipt_json, now, now),
            )
            con.commit()
            return state, result, error, json.loads(receipt_json), True

    def get_receipt(self, operation_id: str) -> dict[str, Any] | None:
        with self._db() as con:
            row = con.execute("SELECT receipt_json FROM executions WHERE operation_id=?", (operation_id,)).fetchone()
        return None if row is None or row[0] is None else json.loads(row[0])

    def save_receipt(self, operation_id: str, binding_digest: str, receipt: Mapping[str, Any]) -> dict[str, Any]:
        encoded = canonical_json_bytes(dict(receipt)).decode("utf-8")
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT binding_digest,receipt_json FROM executions WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None or row["binding_digest"] != binding_digest:
                raise OperationBindingConflict("execution record is missing or has a different binding")
            if row["receipt_json"] is not None and row["receipt_json"] != encoded:
                raise OperationBindingConflict("execution receipt already exists with different content")
            con.execute("UPDATE executions SET receipt_json=? WHERE operation_id=?", (encoded, operation_id))
            con.commit()
        return dict(receipt)
