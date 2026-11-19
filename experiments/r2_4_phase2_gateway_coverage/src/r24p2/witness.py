"""P3 — Witness-registered expected calls (independent key + DB).

The witness registers the coordinator's EXPECTATION that a logical call should
happen. Like Phase 1, REGISTERING an expectation is NOT proof the call executed.
It gives the verifier an independent "there should be evidence for this" anchor
so a missing submission cannot be mistaken for "nothing was expected".
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import WitnessExpectation


class CallWitness:
    def __init__(self, db_path: str | Path, key: Ed25519PrivateKey, witness_id: str):
        self.db_path = str(db_path)
        self.key = key
        self.witness_id = witness_id
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with closing(self._connect()) as con:
            con.execute(
                """CREATE TABLE IF NOT EXISTS expectations (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   run_id TEXT, logical_call_id TEXT, attempt_id TEXT,
                   service_id TEXT, signature TEXT)"""
            )
            con.commit()

    def expect(self, run_id: str, logical_call_id: str, attempt_id: str,
               service_id: str) -> WitnessExpectation:
        we = WitnessExpectation(
            run_id=run_id, logical_call_id=logical_call_id, attempt_id=attempt_id,
            service_id=service_id,
        ).sign(self.key)
        with closing(self._connect()) as con:
            con.execute(
                "INSERT INTO expectations (run_id, logical_call_id, attempt_id, "
                "service_id, signature) VALUES (?,?,?,?,?)",
                (we.run_id, we.logical_call_id, we.attempt_id, we.service_id, we.signature),
            )
            con.commit()
        return we

    def expectations(self) -> list[WitnessExpectation]:
        with closing(self._connect()) as con:
            rows = con.execute(
                "SELECT run_id, logical_call_id, attempt_id, service_id, signature "
                "FROM expectations ORDER BY id"
            ).fetchall()
        return [
            WitnessExpectation(
                run_id=r["run_id"], logical_call_id=r["logical_call_id"],
                attempt_id=r["attempt_id"], service_id=r["service_id"],
                signature=r["signature"],
            )
            for r in rows
        ]

    def count(self) -> int:
        with closing(self._connect()) as con:
            return int(con.execute("SELECT COUNT(*) FROM expectations").fetchone()[0])
