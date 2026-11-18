"""E2.3 External Tool Sink — atomic sink-side idempotency (experiment-only).

This module is the ONLY new core mechanism in E2.3.  It models the end that
actually produces an external side effect, and guarantees that a repeated
request carrying the SAME idempotency key does NOT produce a second committed
effect.

Design constraints (see FEASIBILITY.md):
  * idempotency_key = digest(domain + executor_id + operation_id) — deliberately
    EXCLUDES arguments and binding_digest, so changing arguments cannot dodge
    dedup by producing a new key.
  * request_digest  = digest(domain + executor_id + operation_id + tool_name +
    tool_schema_hash + canonical(ACTUAL arguments)).  The Sink recomputes this
    from the arguments it actually receives; it never trusts a caller-supplied
    digest.  A same-key / different-argument request is therefore detectable.
  * idempotency record + side effect + original result are committed in ONE
    SQLite transaction (BEGIN IMMEDIATE).  We never commit the key first and
    the effect later (that would just recreate an F2 window inside the Sink).

This module does NOT modify production code and does not call a real third-party
API; the "effect" is a durable row in an independent SQLite file.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Mapping

from online_budget.canonical import digest

IDEMPOTENCY_DOMAIN = "e2-3-sink-idempotency-v1"
REQUEST_DOMAIN = "e2-3-sink-request-v1"

OUTCOME_EXECUTED = "EXECUTED"
OUTCOME_DEDUP_HIT = "DEDUP_HIT"
OUTCOME_CONFLICT = "IDEMPOTENCY_KEY_CONFLICT"
OUTCOME_ROLLED_BACK = "ROLLED_BACK"


class IdempotencyKeyConflict(Exception):
    """Raised when the same key is reused with a different request digest."""

    def __init__(self, key: str, expected: str, actual: str) -> None:
        super().__init__(f"idempotency key conflict: key={key}")
        self.key = key
        self.expected_digest = expected
        self.actual_digest = actual


def sink_idempotency_key(*, executor_id: str, operation_id: str) -> str:
    """Stable key per operation identity — intentionally argument-independent."""
    return digest({
        "domain": IDEMPOTENCY_DOMAIN,
        "executor_id": executor_id,
        "operation_id": operation_id,
    })


def sink_request_digest(
    *,
    executor_id: str,
    operation_id: str,
    tool_name: str,
    tool_schema_hash: str,
    arguments: Mapping[str, Any],
) -> str:
    """Recompute the request digest from the arguments the Sink actually got.

    Uses the repository's canonical_json_bytes via digest(); no new JSON profile.
    """
    return digest({
        "domain": REQUEST_DOMAIN,
        "executor_id": executor_id,
        "operation_id": operation_id,
        "tool_name": tool_name,
        "tool_schema_hash": tool_schema_hash,
        "arguments": dict(arguments),
    })


class ExternalToolSink:
    """Independent SQLite-backed tool sink with atomic idempotent execution.

    Tables:
      sink_records — one row per idempotency key: key, request_digest, original
                     result, and the (single) committed effect description.
      dispatch_events — one row per *dispatch attempt* (how many times the tool
                        was called), including dedup-hit and conflict attempts.
      sink_effects   — one row per *committed side effect*.  For V1 this stays at
                        one even across many dispatches; for V0 (no idempotency)
                        it grows with each dispatch.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=30.0)

    def _init_db(self) -> None:
        con = self._connect()
        try:
            con.execute(
                "CREATE TABLE IF NOT EXISTS sink_records("
                "idempotency_key TEXT PRIMARY KEY, request_digest TEXT NOT NULL, "
                "result_json TEXT NOT NULL, effect_json TEXT NOT NULL, "
                "created_at REAL NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS dispatch_events("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, outcome TEXT NOT NULL, created_at REAL NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS sink_effects("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, "
                "idempotency_key TEXT NOT NULL, invoice_id TEXT NOT NULL, created_at REAL NOT NULL)"
            )
            con.commit()
        finally:
            con.close()

    def dispatch(
        self,
        *,
        idempotency_key: str,
        operation_id: str,
        executor_id: str,
        tool_name: str,
        tool_schema_hash: str,
        arguments: Mapping[str, Any],
        result: Mapping[str, Any],
        invoice_id: str,
        enabled: bool,
        rollback_once: bool = False,
    ) -> dict[str, Any]:
        """Atomically execute-or-dedup a tool request.

        Returns a dict with at least ``outcome`` and ``result``.  ``enabled=False``
        models V0 (no sink-side idempotency): every dispatch records a fresh
        effect.  ``rollback_once`` is a test hook that forces the transaction to
        roll back once, so专项测试 can verify key+effect roll back together.
        """
        actual_digest = sink_request_digest(
            executor_id=executor_id, operation_id=operation_id,
            tool_name=tool_name, tool_schema_hash=tool_schema_hash,
            arguments=arguments,
        )
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT request_digest, result_json FROM sink_records WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()

            if rollback_once and row is None:
                # Insert key + effect, then force rollback: both must disappear.
                con.execute(
                    "INSERT INTO sink_records(idempotency_key,request_digest,result_json,effect_json,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (idempotency_key, actual_digest,
                     json.dumps(dict(result), sort_keys=True, ensure_ascii=False),
                     json.dumps({"invoice_id": invoice_id}, sort_keys=True), time.time()),
                )
                con.execute(
                    "INSERT INTO sink_effects(operation_id,idempotency_key,invoice_id,created_at) "
                    "VALUES(?,?,?,?)",
                    (operation_id, idempotency_key, invoice_id, time.time()),
                )
                con.rollback()
                return {"outcome": OUTCOME_ROLLED_BACK, "result": None,
                        "request_digest": actual_digest}

            if not enabled:
                # V0: no sink-side dedup. Every dispatch produces a new effect;
                # still record the attempt for dispatch counting.
                con.execute(
                    "INSERT INTO sink_effects(operation_id,idempotency_key,invoice_id,created_at) "
                    "VALUES(?,?,?,?)",
                    (operation_id, idempotency_key, invoice_id, time.time()),
                )
                con.execute(
                    "INSERT INTO dispatch_events(operation_id,idempotency_key,outcome,created_at) "
                    "VALUES(?,?,?,?)",
                    (operation_id, idempotency_key, OUTCOME_EXECUTED, time.time()),
                )
                con.commit()
                return {"outcome": OUTCOME_EXECUTED, "result": dict(result),
                        "request_digest": actual_digest}

            if row is None:
                # First execution: key + effect + original result in ONE commit.
                con.execute(
                    "INSERT INTO sink_records(idempotency_key,request_digest,result_json,effect_json,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (idempotency_key, actual_digest,
                     json.dumps(dict(result), sort_keys=True, ensure_ascii=False),
                     json.dumps({"invoice_id": invoice_id}, sort_keys=True), time.time()),
                )
                con.execute(
                    "INSERT INTO sink_effects(operation_id,idempotency_key,invoice_id,created_at) "
                    "VALUES(?,?,?,?)",
                    (operation_id, idempotency_key, invoice_id, time.time()),
                )
                con.execute(
                    "INSERT INTO dispatch_events(operation_id,idempotency_key,outcome,created_at) "
                    "VALUES(?,?,?,?)",
                    (operation_id, idempotency_key, OUTCOME_EXECUTED, time.time()),
                )
                con.commit()
                return {"outcome": OUTCOME_EXECUTED, "result": dict(result),
                        "request_digest": actual_digest}

            expected_digest, original_result_json = row
            if expected_digest != actual_digest:
                # Same key, different arguments → reject, no new effect.
                # Record the conflict outcome in the SAME independent DB so the
                # parent can observe it, and return a truthful response object
                # (the Gate decides how to surface it to the Receipt).
                con.execute(
                    "INSERT INTO dispatch_events(operation_id,idempotency_key,outcome,created_at) "
                    "VALUES(?,?,?,?)",
                    (operation_id, idempotency_key, OUTCOME_CONFLICT, time.time()),
                )
                con.commit()
                return {
                    "outcome": OUTCOME_CONFLICT,
                    "result": None,
                    "request_digest": actual_digest,
                    "expected_digest": expected_digest,
                }

            # Same key, same arguments → dedup hit. Return the ORIGINAL result,
            # no new effect row. Dispatch is still counted (工具被调用了第二次).
            con.execute(
                "INSERT INTO dispatch_events(operation_id,idempotency_key,outcome,created_at) "
                "VALUES(?,?,?,?)",
                (operation_id, idempotency_key, OUTCOME_DEDUP_HIT, time.time()),
            )
            con.commit()
            return {"outcome": OUTCOME_DEDUP_HIT,
                    "result": json.loads(original_result_json),
                    "request_digest": actual_digest}
        finally:
            con.close()

    # ---- observation helpers (used by runner and tests) -----------------
    def effect_count(self, operation_id: str) -> int:
        con = self._connect()
        try:
            return int(con.execute(
                "SELECT COUNT(*) FROM sink_effects WHERE operation_id=?", (operation_id,)
            ).fetchone()[0])
        finally:
            con.close()

    def dispatch_count(self, operation_id: str) -> int:
        con = self._connect()
        try:
            return int(con.execute(
                "SELECT COUNT(*) FROM dispatch_events WHERE operation_id=?", (operation_id,)
            ).fetchone()[0])
        finally:
            con.close()

    def outcomes(self, operation_id: str) -> list[str]:
        con = self._connect()
        try:
            return [r[0] for r in con.execute(
                "SELECT outcome FROM dispatch_events WHERE operation_id=? ORDER BY id", (operation_id,)
            ).fetchall()]
        finally:
            con.close()

    def record_exists(self, idempotency_key: str) -> bool:
        con = self._connect()
        try:
            return con.execute(
                "SELECT 1 FROM sink_records WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone() is not None
        finally:
            con.close()

    def original_result(self, idempotency_key: str) -> dict[str, Any] | None:
        con = self._connect()
        try:
            row = con.execute(
                "SELECT result_json FROM sink_records WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            return json.loads(row[0]) if row else None
        finally:
            con.close()
