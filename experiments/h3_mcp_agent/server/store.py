"""SQLite-backed local test store for H3.1 MCP tools.

Every real tool execution writes one unique row into `tool_events` capturing:
effect_id, tool_name, arguments, result, status, timestamp. create/update also
write a row into `effects` (the observable local side effect).

Boundaries:
- This is an ISOLATED TEST database only. No production data, no external account.
- The event log records what the server ACTUALLY received and did; it is the
  ground truth for "MCP Server received a call" and "side effect happened".
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Any, Mapping

from .seed import SEED_RECORDS
from ..tool_specs import TOOL_SPECS, ValidationError, validate_arguments

STATUS_OK = "OK"
STATUS_REJECTED = "REJECTED"  # server-side validation rejected before effect
STATUS_ERROR = "ERROR"


def _dump(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class TestStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
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
                CREATE TABLE IF NOT EXISTS records (
                    record_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tool_events (
                    effect_id TEXT PRIMARY KEY,
                    tool_name TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    has_effect INTEGER NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS effects (
                    effect_id TEXT PRIMARY KEY,
                    tool_name TEXT NOT NULL,
                    target_record_id TEXT,
                    after_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                """
            )
            # Idempotent seed: insert only if table empty.
            cur = con.execute("SELECT COUNT(*) FROM records")
            if cur.fetchone()[0] == 0:
                import time

                now = time.time()
                for rec in SEED_RECORDS:
                    con.execute(
                        "INSERT INTO records(record_id,title,content,created_at) VALUES(?,?,?,?)",
                        (rec["record_id"], rec["title"], rec["content"], now),
                    )
            con.commit()
        finally:
            con.close()

    def _log_event(
        self,
        con: sqlite3.Connection,
        *,
        effect_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        result: Any,
        status: str,
        created_at: float,
    ) -> None:
        has_effect = 1 if TOOL_SPECS.get(tool_name, {}).get("has_effect") else 0
        con.execute(
            "INSERT INTO tool_events(effect_id,tool_name,arguments_json,result_json,status,has_effect,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                effect_id,
                tool_name,
                _dump(dict(arguments)),
                _dump(result),
                status,
                has_effect,
                created_at,
            ),
        )

    def execute(self, tool_name: str, arguments: Any) -> dict[str, Any]:
        """Execute one tool call, validate first, log the ACTUAL result.

        Returns a dict always containing: effect_id, tool_name, status,
        has_effect, result. On validation error, status=REJECTED and result has
        a reason code; NO effect is written.
        """
        import time

        created_at = time.time()
        effect_id = "evt_" + uuid.uuid4().hex
        con = self._connect()
        try:
            try:
                clean = validate_arguments(tool_name, arguments)
            except ValidationError as exc:
                result = {"ok": False, "reason": str(exc)}
                self._log_event(
                    con,
                    effect_id=effect_id,
                    tool_name=tool_name,
                    arguments=arguments if isinstance(arguments, dict) else {"_raw": str(arguments)},
                    result=result,
                    status=STATUS_REJECTED,
                    created_at=created_at,
                )
                con.commit()
                return {
                    "effect_id": effect_id,
                    "tool_name": tool_name,
                    "status": STATUS_REJECTED,
                    "has_effect": False,
                    "result": result,
                }

            if tool_name == "search_records":
                q = clean["query"]
                limit = clean["limit"]
                like = f"%{q}%"
                rows = con.execute(
                    "SELECT record_id,title,content FROM records "
                    "WHERE record_id LIKE ? OR title LIKE ? OR content LIKE ? "
                    "ORDER BY record_id LIMIT ?",
                    (like, like, like, limit),
                ).fetchall()
                found = [
                    {"record_id": r[0], "title": r[1], "content": r[2]} for r in rows
                ]
                result = {"ok": True, "count": len(found), "records": found}
                self._log_event(
                    con,
                    effect_id=effect_id,
                    tool_name=tool_name,
                    arguments=clean,
                    result={"ok": True, "count": len(found), "record_ids": [f["record_id"] for f in found]},
                    status=STATUS_OK,
                    created_at=created_at,
                )
                con.commit()
                return {
                    "effect_id": effect_id,
                    "tool_name": tool_name,
                    "status": STATUS_OK,
                    "has_effect": False,
                    "result": result,
                }

            if tool_name == "create_record":
                new_id = "REC-" + uuid.uuid4().hex[:10].upper()
                con.execute(
                    "INSERT INTO records(record_id,title,content,created_at) VALUES(?,?,?,?)",
                    (new_id, clean["title"], clean["content"], created_at),
                )
                after = {"record_id": new_id, "title": clean["title"], "content": clean["content"]}
                con.execute(
                    "INSERT INTO effects(effect_id,tool_name,target_record_id,after_json,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (effect_id, tool_name, new_id, _dump(after), created_at),
                )
                result = {"ok": True, "record_id": new_id}
                self._log_event(
                    con,
                    effect_id=effect_id,
                    tool_name=tool_name,
                    arguments=clean,
                    result=result,
                    status=STATUS_OK,
                    created_at=created_at,
                )
                con.commit()
                return {
                    "effect_id": effect_id,
                    "tool_name": tool_name,
                    "status": STATUS_OK,
                    "has_effect": True,
                    "result": result,
                }

            if tool_name == "update_record":
                rid = clean["record_id"]
                cur = con.execute(
                    "UPDATE records SET content=? WHERE record_id=?",
                    (clean["content"], rid),
                )
                if cur.rowcount == 0:
                    result = {"ok": False, "reason": "RECORD_NOT_FOUND", "record_id": rid}
                    self._log_event(
                        con,
                        effect_id=effect_id,
                        tool_name=tool_name,
                        arguments=clean,
                        result=result,
                        status=STATUS_ERROR,
                        created_at=created_at,
                    )
                    con.commit()
                    return {
                        "effect_id": effect_id,
                        "tool_name": tool_name,
                        "status": STATUS_ERROR,
                        "has_effect": False,
                        "result": result,
                    }
                after = {"record_id": rid, "content": clean["content"]}
                con.execute(
                    "INSERT INTO effects(effect_id,tool_name,target_record_id,after_json,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (effect_id, tool_name, rid, _dump(after), created_at),
                )
                result = {"ok": True, "record_id": rid}
                self._log_event(
                    con,
                    effect_id=effect_id,
                    tool_name=tool_name,
                    arguments=clean,
                    result=result,
                    status=STATUS_OK,
                    created_at=created_at,
                )
                con.commit()
                return {
                    "effect_id": effect_id,
                    "tool_name": tool_name,
                    "status": STATUS_OK,
                    "has_effect": True,
                    "result": result,
                }

            # Frozen spec has only three tools; defensive fallback.
            result = {"ok": False, "reason": "UNKNOWN_TOOL"}
            self._log_event(
                con,
                effect_id=effect_id,
                tool_name=tool_name,
                arguments=clean,
                result=result,
                status=STATUS_REJECTED,
                created_at=created_at,
            )
            con.commit()
            return {
                "effect_id": effect_id,
                "tool_name": tool_name,
                "status": STATUS_REJECTED,
                "has_effect": False,
                "result": result,
            }
        finally:
            con.close()

    # ---- ground-truth readers (for tests / reports) ----

    def count_effects(self) -> int:
        con = self._connect()
        try:
            return int(con.execute("SELECT COUNT(*) FROM effects").fetchone()[0])
        finally:
            con.close()

    def read_events(self) -> list[dict[str, Any]]:
        con = self._connect()
        try:
            rows = con.execute(
                "SELECT effect_id,tool_name,arguments_json,result_json,status,has_effect,created_at "
                "FROM tool_events ORDER BY created_at,effect_id"
            ).fetchall()
            return [
                {
                    "effect_id": r[0],
                    "tool_name": r[1],
                    "arguments": json.loads(r[2]),
                    "result": json.loads(r[3]),
                    "status": r[4],
                    "has_effect": bool(r[5]),
                    "created_at": r[6],
                }
                for r in rows
            ]
        finally:
            con.close()

    def get_record(self, record_id: str) -> dict[str, Any] | None:
        con = self._connect()
        try:
            row = con.execute(
                "SELECT record_id,title,content FROM records WHERE record_id=?", (record_id,)
            ).fetchone()
            return {"record_id": row[0], "title": row[1], "content": row[2]} if row else None
        finally:
            con.close()
