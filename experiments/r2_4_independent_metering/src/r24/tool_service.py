"""Simulated tool services (untrusted metering reporters).

Each service owns a SEPARATE SQLite DB from the witness and signs its own usage
events with its OWN Ed25519 key. It has no handle to the witness DB/key.

Config A (service self-reported metering): the service maintains its own
counter, signs the value, and that is the ONLY metering evidence available.
It can detect tampering of the record, but cannot detect a lie signed by the
service itself.

Storage model: ``usage_submissions`` is APPEND-ONLY (rowid PK, event_id NOT
unique). This is what the verifier reads, so a duplicate submission produces
two real rows and can be detected. Attack helpers mutate these REAL rows / the
records handed to the verifier; none of them touch verifier internals.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import UsageEvent, UsageStatus


class ToolService:
    def __init__(self, service_id: str, db_path: str | Path, key: Ed25519PrivateKey):
        self.service_id = service_id
        self.db_path = str(db_path)
        self.key = key
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with closing(self._connect()) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS usage_submissions (
                    rowid_pk INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    usage INTEGER NOT NULL,
                    unit TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
                """
            )
            con.commit()

    # ---------------- honest behaviour ----------------
    def emit_usage(
        self,
        event_id: str,
        run_id: str,
        operation_id: str,
        attempt_id: str,
        reported_usage: int,
        unit: str = "unit",
        status: str = UsageStatus.MEASURED.value,
    ) -> UsageEvent:
        ev = UsageEvent(
            event_id=event_id, run_id=run_id, operation_id=operation_id,
            attempt_id=attempt_id, usage=reported_usage, unit=unit,
            status=status, source_id=self.service_id,
        ).sign(self.key)
        self._append(ev)
        return ev

    def _append(self, ev: UsageEvent) -> None:
        with closing(self._connect()) as con:
            con.execute(
                """INSERT INTO usage_submissions
                   (event_id, run_id, operation_id, attempt_id, usage, unit, status, source_id, signature)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (ev.event_id, ev.run_id, ev.operation_id, ev.attempt_id, ev.usage,
                 ev.unit, ev.status, ev.source_id, ev.signature),
            )
            con.commit()

    def all_events(self) -> list[UsageEvent]:
        with closing(self._connect()) as con:
            rows = con.execute("SELECT * FROM usage_submissions ORDER BY rowid_pk ASC").fetchall()
        return [self._row_to_event(r) for r in rows]

    @staticmethod
    def _row_to_event(r: sqlite3.Row) -> UsageEvent:
        return UsageEvent(
            event_id=r["event_id"], run_id=r["run_id"], operation_id=r["operation_id"],
            attempt_id=r["attempt_id"], usage=r["usage"], unit=r["unit"],
            status=r["status"], source_id=r["source_id"], signature=r["signature"],
        )

    # ---------------- attack helpers (mutate REAL rows/records) ----------------
    def suppress_usage(self, event_id: str) -> None:
        """T2/T3 style: delete a metering row from the service's real DB."""
        with closing(self._connect()) as con:
            con.execute("DELETE FROM usage_submissions WHERE event_id=?", (event_id,))
            con.commit()

    def tamper_usage_value(self, event_id: str, new_value: int) -> None:
        """T4: modify signed usage WITHOUT re-signing -> signature breaks."""
        with closing(self._connect()) as con:
            con.execute(
                "UPDATE usage_submissions SET usage=? WHERE event_id=?", (new_value, event_id)
            )
            con.commit()

    def reemit_same_event_same_content(self, ev: UsageEvent) -> None:
        """T5a: append an identical signed record again (same content)."""
        self._append(ev)

    def reemit_same_event_different_content(self, ev: UsageEvent) -> None:
        """T5b: same event_id, DIFFERENT signed content -> conflict."""
        self._append(ev)

    def append_raw_row(self, ev: UsageEvent) -> None:
        """Append a raw (possibly attacker-forged) row for verifier input."""
        self._append(ev)
