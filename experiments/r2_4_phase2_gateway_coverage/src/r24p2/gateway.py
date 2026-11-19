"""P1 — Mandatory enforcement gateway.

The gateway is REAL enforcement, not a convention that "requests go through
it". The service entrance authenticates every incoming request against the
gateway's public key and REFUSES any request without a valid, signed
ForwardReceipt. A caller that bypasses the gateway has no gateway private key
and therefore cannot produce a receipt the service will accept.

Gateway signs: (run_id, logical_call_id, attempt_id, service_id, gateway_id).
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import ForwardReceipt


class Gateway:
    def __init__(self, db_path: str | Path, key: Ed25519PrivateKey, gateway_id: str):
        self.db_path = str(db_path)
        self.key = key
        self.gateway_id = gateway_id
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with closing(self._connect()) as con:
            con.execute(
                """CREATE TABLE IF NOT EXISTS forward_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   run_id TEXT, logical_call_id TEXT, attempt_id TEXT,
                   service_id TEXT, receipt TEXT)"""
            )
            con.commit()

    def forward(self, run_id: str, logical_call_id: str, attempt_id: str,
                service_id: str) -> ForwardReceipt:
        """Accept an agent call and issue a signed forwarding receipt."""
        receipt = ForwardReceipt(
            run_id=run_id, logical_call_id=logical_call_id, attempt_id=attempt_id,
            service_id=service_id, gateway_id=self.gateway_id,
        ).sign(self.key)
        with closing(self._connect()) as con:
            con.execute(
                "INSERT INTO forward_log (run_id, logical_call_id, attempt_id, "
                "service_id, receipt) VALUES (?,?,?,?,?)",
                (run_id, logical_call_id, attempt_id, service_id, receipt.signature),
            )
            con.commit()
        return receipt

    def receipts(self) -> list[ForwardReceipt]:
        """Observable gateway evidence (signed receipts) for verifier views."""
        with closing(self._connect()) as con:
            rows = con.execute(
                "SELECT run_id, logical_call_id, attempt_id, service_id, receipt "
                "FROM forward_log ORDER BY id"
            ).fetchall()
        return [
            ForwardReceipt(
                run_id=r["run_id"], logical_call_id=r["logical_call_id"],
                attempt_id=r["attempt_id"], service_id=r["service_id"],
                gateway_id=self.gateway_id, signature=r["receipt"],
            )
            for r in rows
        ]

    def count(self) -> int:
        with closing(self._connect()) as con:
            return int(con.execute("SELECT COUNT(*) FROM forward_log").fetchone()[0])
