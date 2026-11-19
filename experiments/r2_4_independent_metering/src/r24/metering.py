"""Independent metering module (configuration B/C only).

This is a SIMULATED trusted observation point with its own DB and its own key.
It records the resource consumption PRE-SET by the experiment (the ground
truth number), independent of what the tool service reports.

Trust assumption: this module is honest and its observation equals real usage.
That assumption is exactly what configuration C buys and what configuration A
lacks. It is NOT a real TEE, cloud provider, network tap or third-party API
metering guarantee. Do not present it as one.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import MeteringObservation


class MeteringObserver:
    def __init__(self, observer_id: str, db_path: str | Path, key: Ed25519PrivateKey):
        self.observer_id = observer_id
        self.db_path = str(db_path)
        self.key = key
        self._init_db()

    def _connect_db(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with closing(self._connect_db()) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS metering_observations (
                    event_id TEXT PRIMARY KEY,
                    observed_usage INTEGER NOT NULL,
                    unit TEXT NOT NULL,
                    observer_id TEXT NOT NULL,
                    signature TEXT NOT NULL
                )
                """
            )
            con.commit()

    def observe(self, event_id: str, observed_usage: int, unit: str = "unit") -> MeteringObservation:
        ob = MeteringObservation(
            event_id=event_id, observed_usage=observed_usage, unit=unit,
            observer_id=self.observer_id,
        ).sign(self.key)
        with closing(self._connect_db()) as con:
            con.execute(
                """INSERT INTO metering_observations
                   (event_id, observed_usage, unit, observer_id, signature)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(event_id) DO UPDATE SET
                     observed_usage=excluded.observed_usage, unit=excluded.unit,
                     observer_id=excluded.observer_id, signature=excluded.signature""",
                (ob.event_id, ob.observed_usage, ob.unit, ob.observer_id, ob.signature),
            )
            con.commit()
        return ob

    def all_observations(self) -> list[MeteringObservation]:
        with closing(self._connect_db()) as con:
            rows = con.execute("SELECT * FROM metering_observations ORDER BY rowid ASC").fetchall()
        return [
            MeteringObservation(
                event_id=r["event_id"], observed_usage=r["observed_usage"],
                unit=r["unit"], observer_id=r["observer_id"], signature=r["signature"],
            )
            for r in rows
        ]

    def count(self) -> int:
        with closing(self._connect_db()) as con:
            return int(con.execute("SELECT COUNT(*) FROM metering_observations").fetchone()[0])
