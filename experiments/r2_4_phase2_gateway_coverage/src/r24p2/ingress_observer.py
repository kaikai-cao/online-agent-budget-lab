"""P2 — Independent service-ingress observer.

Trust boundary: the observer owns its OWN SQLite DB and OWN Ed25519 key, and
the service is never given a handle to either. It observes requests that reach
the service *entrance*, independently of what the service later claims.

An observer record is signed evidence that "a request with this identity
reached the entrance and carried (or lacked) a valid gateway proof". It does
NOT claim the service executed the operation (entrance observed != executed).

T5 simulates the observer losing a record (crash / unavailable): the record is
simply not present in its DB, but the controller's ground truth still knows the
call was accepted. A correct scheme must answer UNCERTAIN, not "complete".
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import IngressObservation


class IngressObserver:
    def __init__(self, db_path: str | Path, key: Ed25519PrivateKey, observer_id: str):
        self.db_path = str(db_path)
        self.key = key
        self.observer_id = observer_id
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with closing(self._connect()) as con:
            con.execute(
                """CREATE TABLE IF NOT EXISTS ingress_events (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   run_id TEXT, logical_call_id TEXT, attempt_id TEXT,
                   service_id TEXT, gateway_authenticated INTEGER, signature TEXT)"""
            )
            con.commit()

    def observe(self, run_id: str, logical_call_id: str, attempt_id: str,
                service_id: str, gateway_authenticated: bool,
                drop_record: bool = False) -> IngressObservation | None:
        """Record an entrance observation.

        ``gateway_authenticated`` is determined by the observer's OWN check of
        the gateway proof, not by what the service says.
        ``drop_record=True`` simulates T5: evidence lost, nothing persisted.
        """
        ob = IngressObservation(
            run_id=run_id, logical_call_id=logical_call_id, attempt_id=attempt_id,
            service_id=service_id, observer_id=self.observer_id,
            gateway_authenticated=gateway_authenticated,
        ).sign(self.key)
        if drop_record:
            return None  # simulated loss: no evidence written
        with closing(self._connect()) as con:
            con.execute(
                "INSERT INTO ingress_events (run_id, logical_call_id, attempt_id, "
                "service_id, gateway_authenticated, signature) VALUES (?,?,?,?,?,?)",
                (ob.run_id, ob.logical_call_id, ob.attempt_id, ob.service_id,
                 1 if ob.gateway_authenticated else 0, ob.signature),
            )
            con.commit()
        return ob

    def observations(self) -> list[IngressObservation]:
        with closing(self._connect()) as con:
            rows = con.execute(
                "SELECT run_id, logical_call_id, attempt_id, service_id, "
                "gateway_authenticated, signature FROM ingress_events ORDER BY id"
            ).fetchall()
        return [
            IngressObservation(
                run_id=r["run_id"], logical_call_id=r["logical_call_id"],
                attempt_id=r["attempt_id"], service_id=r["service_id"],
                observer_id=self.observer_id,
                gateway_authenticated=bool(r["gateway_authenticated"]),
                signature=r["signature"],
            )
            for r in rows
        ]

    def count(self) -> int:
        with closing(self._connect()) as con:
            return int(con.execute("SELECT COUNT(*) FROM ingress_events").fetchone()[0])
