"""Independent one-time dispatch-consumption store for H3.2.

CRITICAL BOUNDARY (do not blur):
- This store atomically consumes a ``jti`` (BEGIN IMMEDIATE + jti PRIMARY KEY)
  and, on first consumption, grants the Host permission to issue ONE MCP
  tools/call. A second consumption of the same jti returns DEDUP_HIT and MUST
  NOT dispatch again.
- The side effect produced by that MCP call happens in a SEPARATE MCP Server
  process and a SEPARATE SQLite database. It is NOT in the same transaction as
  this jti consumption. We do NOT claim atomicity between them.
- If consumption succeeded but the MCP call failed, the state is
  DISPATCH_UNCERTAIN: the jti is already spent, we record the uncertainty and
  NEVER auto-retry (a retry would either be denied as a duplicate or, if we
  forced it, could double-apply an unknown effect).

This class implements the same ``consume_and_effect`` signature as H1's
ControlledSink so the FROZEN H1 Executor can be reused without modification.
Here the "result" is a dispatch-permission record, not a controlled side effect.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Mapping

from .h1_bridge import OUTCOME_DEDUP_HIT, OUTCOME_EXECUTED, OUTCOME_ROLLED_BACK

DISPATCH_UNCERTAIN = "DISPATCH_UNCERTAIN"
DISPATCH_OK = "DISPATCH_OK"
DISPATCH_SKIPPED = "DISPATCH_SKIPPED"  # consumed but a policy/gate skipped dispatch


class DispatchConsumptionStore:
    """Executor-local, SQLite-backed one-time dispatch permission store."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        # Last successful consume duration (ms); read by the adapter to split
        # verification cost from one-time-consumption cost. Not a model timing.
        self.last_consume_ms: float | None = None
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10.0)
        con.execute("PRAGMA busy_timeout=5000")
        return con

    def _init_db(self) -> None:
        con = self._connect()
        try:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS consumptions (
                    jti TEXT PRIMARY KEY,
                    action_digest TEXT NOT NULL,
                    path TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dispatch_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    jti TEXT NOT NULL,
                    status TEXT NOT NULL,
                    detail TEXT,
                    created_at REAL NOT NULL
                );
                """
            )
            con.commit()
        finally:
            con.close()

    # -- H1 ControlledSink-compatible interface (reused by frozen Executor) --

    def consume_and_effect(
        self,
        *,
        jti: str,
        action_digest: str,
        path: str,
        result: Mapping[str, Any],
        rollback_once: bool = False,
    ) -> dict[str, Any]:
        """Atomically consume jti and grant one dispatch permission.

        - new jti: insert consumption + DISPATCH_OK intent, one commit; returns
          outcome=EXECUTED meaning "dispatch is now permitted once".
        - duplicate jti: outcome=DEDUP_HIT, original result returned, no new
          dispatch permission is granted.
        - rollback_once: insert then roll back both, so a later retry can
          succeed (used by deterministic crash-window tests only).
        """
        result_json = json.dumps(result, sort_keys=True, separators=(",", ":"))
        _t_consume = time.perf_counter()
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT result_json FROM consumptions WHERE jti=?", (jti,)
            ).fetchone()
            if row is not None:
                con.execute(
                    "INSERT INTO dispatch_events(jti,status,detail,created_at) VALUES(?,?,?,?)",
                    (jti, DISPATCH_SKIPPED, "DEDUP_HIT", time.time()),
                )
                con.commit()
                return {
                    "outcome": OUTCOME_DEDUP_HIT,
                    "result": json.loads(row[0]),
                    "path": path,
                }

            con.execute(
                "INSERT INTO consumptions(jti,action_digest,path,result_json,created_at) "
                "VALUES(?,?,?,?,?)",
                (jti, action_digest, path, result_json, time.time()),
            )
            if rollback_once:
                con.rollback()
                return {"outcome": OUTCOME_ROLLED_BACK, "result": None, "path": path}
            con.execute(
                "INSERT INTO dispatch_events(jti,status,detail,created_at) VALUES(?,?,?,?)",
                (jti, DISPATCH_OK, "CONSUMPTION_GRANTED", time.time()),
            )
            con.commit()
            self.last_consume_ms = round((time.perf_counter() - _t_consume) * 1000.0, 4)
            return {"outcome": OUTCOME_EXECUTED, "result": result, "path": path}
        except sqlite3.IntegrityError:
            # Another transaction won the jti race first.
            con.rollback()
            row = con.execute(
                "SELECT result_json FROM consumptions WHERE jti=?", (jti,)
            ).fetchone()
            con.execute(
                "INSERT INTO dispatch_events(jti,status,detail,created_at) VALUES(?,?,?,?)",
                (jti, DISPATCH_SKIPPED, "DEDUP_HIT_RACE", time.time()),
            )
            con.commit()
            return {
                "outcome": OUTCOME_DEDUP_HIT,
                "result": json.loads(row[0]) if row else None,
                "path": path,
            }
        finally:
            con.close()

    # -- dispatch outcome recording (called by the adapter/Host) --

    def record_dispatch_outcome(
        self, jti: str, status: str, detail: str | None = None
    ) -> None:
        con = self._connect()
        try:
            con.execute(
                "INSERT INTO dispatch_events(jti,status,detail,created_at) VALUES(?,?,?,?)",
                (jti, status, detail, time.time()),
            )
            con.commit()
        finally:
            con.close()

    # -- ground-truth readers --

    def consumption_count(self) -> int:
        con = self._connect()
        try:
            return int(con.execute("SELECT COUNT(*) FROM consumptions").fetchone()[0])
        finally:
            con.close()

    def was_consumed(self, jti: str) -> bool:
        con = self._connect()
        try:
            return con.execute(
                "SELECT 1 FROM consumptions WHERE jti=?", (jti,)
            ).fetchone() is not None
        finally:
            con.close()

    def event_counts(self) -> dict[str, int]:
        con = self._connect()
        try:
            rows = con.execute(
                "SELECT status, COUNT(*) FROM dispatch_events GROUP BY status"
            ).fetchall()
            return {r[0]: int(r[1]) for r in rows}
        finally:
            con.close()
