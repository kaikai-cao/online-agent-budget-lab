"""Controlled Sink + shared one-time consumption store for H1.

Both B2 and C share this EXACT SAME executor-local consumption store and
controlled sink. The one-time consumption state and the controlled side effect
are committed in ONE SQLite transaction (BEGIN IMMEDIATE + jti PRIMARY KEY).
Therefore anti-replay comes from executor-local atomic state, NOT from the
Ed25519 signature and NOT from the B2 online query.

Boundaries:
- The atomic transaction covers only this controlled SQLite Sink; it does NOT
  imply exactly-once for any real third-party API.
- One-time consumption is scoped to THIS store (single executor), not global
  across multiple executors.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Mapping

OUTCOME_EXECUTED = "EXECUTED"
OUTCOME_DEDUP_HIT = "DEDUP_HIT"
OUTCOME_ROLLED_BACK = "ROLLED_BACK"


class ControlledSink:
    """SQLite-backed executor-local consumption store + controlled side effect."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
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
                CREATE TABLE IF NOT EXISTS effects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    jti TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attempt_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    jti TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    path TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )
            con.commit()
        finally:
            con.close()

    def consume_and_effect(
        self,
        *,
        jti: str,
        action_digest: str,
        path: str,
        result: Mapping[str, Any],
        rollback_once: bool = False,
    ) -> dict[str, Any]:
        """Atomically consume jti and commit the controlled side effect.

        - new jti: insert consumption + effect + EXECUTED event, one commit.
        - duplicate jti: DEDUP_HIT, no new effect, return the ORIGINAL result.
        - rollback_once (crash-before-commit simulation): insert then roll back
          both consumption and effect together, so a later retry can succeed.
        """
        result_json = json.dumps(result, sort_keys=True, separators=(",", ":"))
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT result_json FROM consumptions WHERE jti=?", (jti,)
            ).fetchone()
            if row is not None:
                con.execute(
                    "INSERT INTO attempt_events(jti,outcome,path,created_at) VALUES(?,?,?,?)",
                    (jti, OUTCOME_DEDUP_HIT, path, time.time()),
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
            con.execute(
                "INSERT INTO effects(jti,result_json,created_at) VALUES(?,?,?)",
                (jti, result_json, time.time()),
            )
            if rollback_once:
                con.rollback()
                return {"outcome": OUTCOME_ROLLED_BACK, "result": None, "path": path}
            con.execute(
                "INSERT INTO attempt_events(jti,outcome,path,created_at) VALUES(?,?,?,?)",
                (jti, OUTCOME_EXECUTED, path, time.time()),
            )
            con.commit()
            return {"outcome": OUTCOME_EXECUTED, "result": result, "path": path}
        except sqlite3.IntegrityError:
            # Another concurrent transaction won the jti race first.
            con.rollback()
            row = con.execute(
                "SELECT result_json FROM consumptions WHERE jti=?", (jti,)
            ).fetchone()
            con.execute(
                "INSERT INTO attempt_events(jti,outcome,path,created_at) VALUES(?,?,?,?)",
                (jti, OUTCOME_DEDUP_HIT, path, time.time()),
            )
            con.commit()
            return {
                "outcome": OUTCOME_DEDUP_HIT,
                "result": json.loads(row[0]) if row else None,
                "path": path,
            }
        finally:
            con.close()

    def effect_count(self) -> int:
        con = self._connect()
        try:
            return int(con.execute("SELECT COUNT(*) FROM effects").fetchone()[0])
        finally:
            con.close()

    def consumption_count(self) -> int:
        con = self._connect()
        try:
            return int(con.execute("SELECT COUNT(*) FROM consumptions").fetchone()[0])
        finally:
            con.close()

    def outcome_counts(self) -> dict[str, int]:
        con = self._connect()
        try:
            rows = con.execute(
                "SELECT outcome, COUNT(*) FROM attempt_events GROUP BY outcome"
            ).fetchall()
            return {r[0]: int(r[1]) for r in rows}
        finally:
            con.close()
