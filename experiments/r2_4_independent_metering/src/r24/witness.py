"""Independent Event Witness.

Independence is enforced structurally in this prototype:
  1. Its SQLite DB is SEPARATE from any tool-service DB (own connection/ file).
  2. Its signing key is SEPARATE from tool-service and observer keys.
  3. Tool services are never handed a handle to the Witness DB or key, so they
     have no API to modify an already-registered event.

This is LOGICAL independence inside one process, NOT hardware isolation or
cross-organization trust. Do not overstate it.

The witness registers EXECUTION INTENT. REGISTERED must never be read as proof
that execution actually occurred.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import (
    LEGAL_TRANSITIONS,
    ExecutionEvent,
    ExecStatus,
    is_legal_transition,
)


class EventWitness:
    def __init__(self, db_path: str | Path, key: Ed25519PrivateKey, service_ids: list[str]):
        self.db_path = str(db_path)
        self.key = key
        self.service_ids = list(service_ids)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with closing(self._connect()) as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_events (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    service_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    sequence_no INTEGER NOT NULL,
                    request_digest TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    witness_signature TEXT NOT NULL
                )
                """
            )
            con.commit()

    def register_intent(
        self,
        run_id: str,
        service_id: str,
        operation_id: str,
        attempt_id: str,
        event_id: str,
        request_digest: str,
        registered_at: str,
    ) -> ExecutionEvent:
        """Register an execution intent. Fails closed on duplicate event_id.

        Also fails closed when ``service_id`` is NOT in this witness's configured
        allow-list (``service_ids``). The witness only registers intents for
        services it was configured to observe; an unknown/unlisted service must
        never enter its log. Rejection happens BEFORE any DB write.
        """
        if service_id not in self.service_ids:
            raise ValueError(
                f"service_id {service_id!r} not in witness allowlist {self.service_ids!r}"
            )
        with closing(self._connect()) as con:
            row = con.execute(
                "SELECT sequence_no FROM execution_events ORDER BY sequence_no DESC LIMIT 1"
            ).fetchone()
            seq = (int(row["sequence_no"]) + 1) if row else 1
            event = ExecutionEvent(
                run_id=run_id,
                service_id=service_id,
                operation_id=operation_id,
                attempt_id=attempt_id,
                event_id=event_id,
                sequence_no=seq,
                request_digest=request_digest,
                registered_at=registered_at,
                status=ExecStatus.REGISTERED.value,
            ).sign(self.key)
            con.execute(
                """INSERT INTO execution_events
                   (event_id, run_id, service_id, operation_id, attempt_id,
                    sequence_no, request_digest, registered_at, status, witness_signature)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    event.event_id, event.run_id, event.service_id, event.operation_id,
                    event.attempt_id, event.sequence_no, event.request_digest,
                    event.registered_at, event.status, event.witness_signature,
                ),
            )
            con.commit()
            return event

    def advance_status(self, event_id: str, new_status: str) -> bool:
        """Advance status ONLY along a legal transition. Only witness may call.

        Enforcement (this is the whole point of the state machine):
          * new_status must be a DEFINED ExecStatus value;
          * (old_status, new_status) must be in LEGAL_TRANSITIONS;
          * on rejection the DB row (status AND signature) is left UNCHANGED;
          * FINALIZED has an empty outgoing set -> irreversible;
          * UNCERTAIN -> FINALIZED is illegal; only UNCERTAIN -> CORRECTED is
            allowed, so the uncertain-bypass path cannot settle directly.

        Returns True iff a legal transition was applied.
        """
        # 1. undefined status string -> reject before touching the DB
        if new_status not in {s.value for s in ExecStatus}:
            return False
        with closing(self._connect()) as con:
            row = con.execute(
                "SELECT * FROM execution_events WHERE event_id=?", (event_id,)
            ).fetchone()
            if row is None:
                return False
            old_status = row["status"]
            # 2. illegal jump -> reject, no write, record byte-identical
            if not is_legal_transition(old_status, new_status):
                return False
            event = ExecutionEvent(
                run_id=row["run_id"], service_id=row["service_id"],
                operation_id=row["operation_id"], attempt_id=row["attempt_id"],
                event_id=row["event_id"], sequence_no=row["sequence_no"],
                request_digest=row["request_digest"], registered_at=row["registered_at"],
                status=new_status,
            ).sign(self.key)
            con.execute(
                "UPDATE execution_events SET status=?, witness_signature=? WHERE event_id=?",
                (event.status, event.witness_signature, event_id),
            )
            con.commit()
            return True

    def all_events(self) -> list[ExecutionEvent]:
        """Read-only snapshot for the verifier. No service ever gets this handle."""
        with closing(self._connect()) as con:
            rows = con.execute(
                "SELECT * FROM execution_events ORDER BY sequence_no ASC"
            ).fetchall()
        return [
            ExecutionEvent(
                run_id=r["run_id"], service_id=r["service_id"],
                operation_id=r["operation_id"], attempt_id=r["attempt_id"],
                event_id=r["event_id"], sequence_no=r["sequence_no"],
                request_digest=r["request_digest"], registered_at=r["registered_at"],
                status=r["status"], witness_signature=r["witness_signature"],
            )
            for r in rows
        ]

    def event_count(self) -> int:
        with closing(self._connect()) as con:
            return int(con.execute("SELECT COUNT(*) FROM execution_events").fetchone()[0])
