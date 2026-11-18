"""E1.9-B -- persistent, content-sensitive idempotency (B.5).

Invariants (E1.9-B2 §5.5 / B2.1 R3):
  * idempotency key = ``(operation_id, phase)``;
  * same key + same canonical payload  -> return the ORIGINAL Entry (no append);
  * same key + different canonical payload -> ``IdempotencyConflict`` (reject);
  * never modify ``AuthorityJournal.append``; idempotency is a SERVICE-layer
    addition;
  * the index is PERSISTENT (its own SQLite file) and works after a restart;
  * concurrency is controlled by a server-side authoritative SQLite
    ``BEGIN IMMEDIATE`` transaction, not merely an in-process Python lock.

Two-tier authority (crash-safe without cross-store atomicity):
  * the durable idempotency table is the fast index;
  * the signed Journal entries are the AUTHORITATIVE truth.  If an append
    succeeded but the fast-index write was lost (crash between the two), a
    later request finds no fast-index row and FALLS BACK to scanning the signed
    Journal for the (operation_id, phase).  Because the Journal entry carries
    the frozen ``payload_digest`` inside a signed object, the fallback is exact
    and cannot be forged.  Thus "append succeeded / index lost" degrades to a
    correct idempotent replay instead of a duplicate entry.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

from . import journal as jmod


class IdempotencyConflict(ValueError):
    """Same (operation_id, phase) with a different canonical payload."""


class IdempotencyStore:
    """Persistent fast index keyed by (operation_id, phase)."""

    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("PRAGMA synchronous=FULL")
        return con

    @contextmanager
    def _db(self):
        con = self._connect()
        try:
            yield con
        finally:
            if con.in_transaction:
                con.rollback()
            con.close()

    def _init_tables(self) -> None:
        with self._db() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute(
                "CREATE TABLE IF NOT EXISTS idempotency ("
                "operation_id TEXT NOT NULL, phase TEXT NOT NULL, "
                "payload_digest TEXT NOT NULL, seq INTEGER NOT NULL, "
                "entry_digest TEXT NOT NULL, "
                "PRIMARY KEY (operation_id, phase))"
            )

    @contextmanager
    def authoritative_write(self):
        """Hold a SQLite write lock for the whole check->append->record window.

        ``BEGIN IMMEDIATE`` on this dedicated DB is the server-side authoritative
        serialisation point: all writer IPC calls take this lock, so concurrent
        requests for the same key cannot both pass the idempotency check.
        """
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                yield con
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise
            else:
                # Commit the idempotency index write on the success path.  Without
                # this the write is rolled back by _db().__exit__, leaving the
                # index permanently empty (only the signed-Journal fallback would
                # make retries look idempotent).
                if con.in_transaction:
                    con.commit()

    def get(self, con: sqlite3.Connection, operation_id: str, phase: str) -> dict[str, Any] | None:
        row = con.execute(
            "SELECT operation_id, phase, payload_digest, seq, entry_digest "
            "FROM idempotency WHERE operation_id=? AND phase=?",
            (operation_id, phase),
        ).fetchone()
        return dict(row) if row is not None else None

    def put(
        self,
        con: sqlite3.Connection,
        *,
        operation_id: str,
        phase: str,
        payload_digest: str,
        seq: int,
        entry_digest: str,
    ) -> None:
        con.execute(
            "INSERT OR REPLACE INTO idempotency"
            "(operation_id, phase, payload_digest, seq, entry_digest) VALUES(?,?,?,?,?)",
            (operation_id, phase, payload_digest, seq, entry_digest),
        )


def payload_digest_for(phase: str, envelope: Mapping[str, Any]) -> str:
    """Compute the frozen payload_digest using the E1.9-A core functions."""
    if phase == "INTENT":
        return jmod._intent_payload_digest(envelope)
    if phase == "RESULT":
        return jmod._result_payload_digest(envelope)
    raise ValueError(f"unknown phase {phase!r}")


def find_signed_entry(
    journal: jmod.AuthorityJournal, *, operation_id: str, phase: str
) -> dict[str, Any] | None:
    """Authoritative fallback: locate an entry in the signed Journal by key.

    Reads entry_json directly from the Journal DB (never trusting unsigned
    helper columns for the decision) and re-verifies each candidate with the
    core verifier.  Returns the verified signed entry or None.
    """
    with journal._db() as con:
        rows = con.execute(
            "SELECT entry_json FROM journal_entries WHERE operation_id=? AND phase=?",
            (operation_id, phase),
        ).fetchall()
    for row in rows:
        entry = json.loads(row["entry_json"])
        journal._verify_entry(entry)  # fail closed on any tampered signed object
        if entry["operation_id"] == operation_id and entry["phase"] == phase:
            return entry
    return None


__all__ = [
    "IdempotencyConflict",
    "IdempotencyStore",
    "payload_digest_for",
    "find_signed_entry",
]
