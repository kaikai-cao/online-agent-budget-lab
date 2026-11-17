"""E1.9-A -- independent authoritative append-only Journal (Python core).

This module is the E1.9-A "Journal Foundation" deliverable. It is a *new*,
self-contained component: it does NOT touch ``executor.py``, ``execution_store.py``
execution flow, the E1.5 four gates, or any D10/D11 credential structure.

What this component provides (verifiable in this environment):
  * a single global, gap-free, strictly increasing ``seq``;
  * a ``prev_digest`` hash chain over the whole log prefix;
  * an Ed25519 ``entry_signature`` on every JournalEntry;
  * an Ed25519 ``checkpoint_signature`` on every Checkpoint, stored as a
    per-seq historical snapshot (``checkpoint_at(seq)``);
  * full-prefix integrity verification (``verify_integrity``): re-derives every
    digest/signature, checks seq continuity, prev_digest linkage, phase order
    (INTENT before RESULT), checkpoint->head binding, AND that the unsigned
    SQLite helper columns match the signed entry_json; any mismatch raises
    ``JournalIntegrityError`` (fail-closed);
  * identity & helper-column hardening (E1.9-A.1): the outer ``operation_id`` is
    bound to the envelope's ``operation_id`` both on append and on verify; and
    RESULT's inherited ``executor_id`` is read from the signed INTENT entry_json
    (re-verified on read), never from an unsigned SQLite helper column;
  * physical separation: the Journal lives in its own SQLite file injected by
    the caller, with its own signing key, independent of the Executor DB.

Honest trust-boundary statement (E1.9 §1.4 / E1.8 §2.2):
  "separate file + separate key" gives COMPONENT isolation and detects IN-PLACE
  tampering (J06/J07/J08). It does NOT prove anti-rollback against an attacker
  who can restore BOTH the Executor DB and this Journal file (both sit in one
  filesystem / one OS principal / one backup domain in this single-host
  prototype). Recovering an Executor DB snapshot leaving the Journal untouched
  (J10) only demonstrates physical separation. True B2 anti-rollback needs an
  independent trust domain (remote authoritative service, separate OS principal,
  WORM storage, or a monotonic anchor); that is a deployment requirement, not a
  property this file can assert. See docs/E1_9_A_JOURNAL_FOUNDATION.md.

Frozen encodings (domain tags are new in E1.9-A, frozen here):
  * INTENT payload_digest = canonical_digest("e1-journal-intent-v1",
        {operation_id, binding_digest, executor_id})
  * RESULT payload_digest = canonical_digest("e1-result-envelope-v1",
        {operation_id, binding_digest, result, execution_receipt})
    (envelope object per E1.8 §5.2; domain tag defined there, encoding fixed here)
  * entry_digest = canonical_digest("e1-journal-entry-v1", unsigned_entry)
  * entry_signature = Ed25519(authority, canonical_json(
        {"domain": "e1-journal-entry-sign-v1", "entry_digest": entry_digest}))
  * journal_head_digest(seq) = entry_digest of the entry at that seq
  * checkpoint_digest = canonical_digest("e1-journal-checkpoint-v1",
        {seq, journal_head_digest})
  * checkpoint_signature = Ed25519(authority, canonical_json(
        {"domain": "e1-journal-checkpoint-sign-v1",
         "checkpoint_digest": checkpoint_digest}))
  * GENESIS_PREV_DIGEST = canonical_digest("e1-journal-genesis-v1", {})

All digest/signature primitives are REUSED from the frozen E1.1 encoding layer
(``canonical.py`` / ``e1_encoding.py``); no new hash construction is introduced.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import e1_encoding as enc
from .canonical import (
    b64encode,
    canonical_json_bytes,
    verify_signature,
)

# --- Frozen domain tags (E1.9-A) ------------------------------------------------
DOMAIN_INTENT = "e1-journal-intent-v1"
DOMAIN_RESULT_ENVELOPE = "e1-result-envelope-v1"
DOMAIN_ENTRY = "e1-journal-entry-v1"
DOMAIN_ENTRY_SIGN = "e1-journal-entry-sign-v1"
DOMAIN_CHECKPOINT = "e1-journal-checkpoint-v1"
DOMAIN_CHECKPOINT_SIGN = "e1-journal-checkpoint-sign-v1"
DOMAIN_GENESIS = "e1-journal-genesis-v1"

GENESIS_PREV_DIGEST = enc.canonical_digest(DOMAIN_GENESIS, {})

_ENTRY_FIELDS = frozenset(
    {
        "seq",
        "prev_digest",
        "operation_id",
        "phase",
        "executor_id",
        "envelope",
        "payload_digest",
        "entry_digest",
        "entry_signature",
    }
)
_UNSIGNED_ENTRY_FIELDS = (
    "seq",
    "prev_digest",
    "operation_id",
    "phase",
    "executor_id",
    "payload_digest",
)
_UNSIGNED_CHECKPOINT_FIELDS = ("seq", "journal_head_digest")
_CHECKPOINT_FIELDS = frozenset(
    {"seq", "journal_head_digest", "checkpoint_digest", "checkpoint_signature"}
)
_VALID_PHASES = frozenset({"INTENT", "RESULT"})


class JournalError(ValueError):
    """Base class for Journal operational errors (bad input / bad ordering)."""


class JournalIntegrityError(JournalError):
    """The stored log failed integrity verification. Caller must fail closed."""


def _sign(key: Ed25519PrivateKey, payload: Mapping[str, Any]) -> str:
    return b64encode(key.sign(canonical_json_bytes(dict(payload))))


def _verify(key: Ed25519PublicKey, signature_b64: str, payload: Mapping[str, Any]) -> None:
    try:
        verify_signature(key, signature_b64, dict(payload))
    except ValueError as exc:
        raise JournalIntegrityError("journal signature verification failed") from exc


def _intent_payload_digest(envelope: Mapping[str, Any]) -> str:
    """INTENT payload_digest per frozen E1.9-A encoding (fails closed on shape)."""
    if set(envelope) != {"operation_id", "binding_digest", "executor_id"}:
        raise JournalError(
            "INTENT envelope must be exactly {operation_id, binding_digest, executor_id}"
        )
    return enc.canonical_digest(DOMAIN_INTENT, dict(envelope))


def _result_payload_digest(envelope: Mapping[str, Any]) -> str:
    """RESULT payload_digest per E1.8 §5.2 envelope (encoding fixed here)."""
    if set(envelope) != {"operation_id", "binding_digest", "result", "execution_receipt"}:
        raise JournalError(
            "RESULT envelope must be exactly "
            "{operation_id, binding_digest, result, execution_receipt}"
        )
    return enc.canonical_digest(DOMAIN_RESULT_ENVELOPE, dict(envelope))


def _entry_unsigned(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {name: entry[name] for name in _UNSIGNED_ENTRY_FIELDS}


def _entry_digest(unsigned: Mapping[str, Any]) -> str:
    return enc.canonical_digest(DOMAIN_ENTRY, dict(unsigned))


def _entry_sign_message(entry_digest: str) -> dict[str, str]:
    return {"domain": DOMAIN_ENTRY_SIGN, "entry_digest": entry_digest}


def _checkpoint_unsigned(checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    return {name: checkpoint[name] for name in _UNSIGNED_CHECKPOINT_FIELDS}


def _checkpoint_digest(unsigned: Mapping[str, Any]) -> str:
    return enc.canonical_digest(DOMAIN_CHECKPOINT, dict(unsigned))


def _checkpoint_sign_message(checkpoint_digest: str) -> dict[str, str]:
    return {"domain": DOMAIN_CHECKPOINT_SIGN, "checkpoint_digest": checkpoint_digest}


class AuthorityJournal:
    """Independent authoritative append-only Journal.

    ``journal_path`` MUST be a SQLite file distinct from the Executor DB; the
    component never opens or imports the Executor store. ``signing_key`` is the
    authority's Ed25519 private key (kept independent of D10/D11/E1 keys);
    ``verify_key`` is its public counterpart, used for all read/verify paths.
    """

    def __init__(
        self,
        journal_path: str | Path,
        *,
        signing_key: Ed25519PrivateKey,
        verify_key: Ed25519PublicKey,
    ) -> None:
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise JournalError("signing_key must be an Ed25519PrivateKey")
        if not isinstance(verify_key, Ed25519PublicKey):
            raise JournalError("verify_key must be an Ed25519PublicKey")
        self.path = Path(journal_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._signing_key = signing_key
        self._verify_key = verify_key
        self._init_tables()

    # -- persistence ------------------------------------------------------------
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
                "CREATE TABLE IF NOT EXISTS journal_entries ("
                "seq INTEGER PRIMARY KEY, operation_id TEXT NOT NULL, phase TEXT NOT NULL, "
                "executor_id TEXT NOT NULL, entry_digest TEXT NOT NULL, entry_json TEXT NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS journal_checkpoints ("
                "seq INTEGER PRIMARY KEY, checkpoint_json TEXT NOT NULL)"
            )

    # -- append -----------------------------------------------------------------
    def append(self, *, phase: str, operation_id: str, envelope: Mapping[str, Any]) -> dict[str, Any]:
        """Append one INTENT or RESULT entry, sign it, and seal a new checkpoint.

        Runs the seq allocation, linkage, entry write and checkpoint write in a
        single SQLite ``BEGIN IMMEDIATE`` transaction so concurrent appenders
        get a single global, gap-free seq. The transaction is purely *within*
        the Journal file; it makes no claim about cross-store atomicity.
        """
        if phase not in _VALID_PHASES:
            raise JournalError(f"phase must be one of {sorted(_VALID_PHASES)}")
        if not isinstance(operation_id, str) or not operation_id:
            raise JournalError("operation_id must be a non-empty string")
        if not isinstance(envelope, Mapping):
            raise JournalError("envelope must be a mapping")
        # E1.9-A.1 fix #1: the outer operation_id MUST equal the operation_id
        # committed inside the signed envelope. Otherwise an entry can carry
        # identity A in its signed header while promising envelope identity B,
        # causing ambiguity for every downstream lookup keyed by operation_id.
        env_op = envelope.get("operation_id")
        if not isinstance(env_op, str) or not env_op:
            raise JournalError("envelope.operation_id must be a non-empty string")
        if env_op != operation_id:
            raise JournalError(
                "envelope.operation_id must equal the outer operation_id argument"
            )

        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                last = con.execute(
                    "SELECT entry_json FROM journal_entries ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                seq = 1 if last is None else int(json.loads(last["entry_json"])["seq"]) + 1
                prev_digest = GENESIS_PREV_DIGEST if last is None else self._entry_digest_from_json(
                    last["entry_json"]
                )

                # E1.9-A.1 fix #2: executor_id is taken from the SIGNED envelope
                # for INTENT and inherited from the SIGNED prior INTENT entry_json
                # for RESULT. The unsigned SQLite helper columns are indexes only
                # and must never decide a security-sensitive credential field.
                if phase == "INTENT":
                    payload_digest = _intent_payload_digest(envelope)  # validates exact shape first
                    executor_id = envelope["executor_id"]
                    env_obj = dict(envelope)
                else:
                    # INTENT-before-RESULT (E1.8 §7.1) and identity inheritance
                    # are both resolved from verified, signed entry_json.
                    executor_id = self._executor_id_from_signed_intent(con, operation_id)
                    payload_digest = _result_payload_digest(envelope)
                    env_obj = dict(envelope)

                unsigned = {
                    "seq": seq,
                    "prev_digest": prev_digest,
                    "operation_id": operation_id,
                    "phase": phase,
                    "executor_id": executor_id,
                    "payload_digest": payload_digest,
                }
                e_digest = _entry_digest(unsigned)
                entry = {
                    **unsigned,
                    "envelope": env_obj,
                    "entry_digest": e_digest,
                    "entry_signature": _sign(self._signing_key, _entry_sign_message(e_digest)),
                }
                con.execute(
                    "INSERT INTO journal_entries(seq, operation_id, phase, executor_id, entry_digest, entry_json) "
                    "VALUES(?, ?, ?, ?, ?, ?)",
                    (
                        seq,
                        operation_id,
                        phase,
                        executor_id,
                        e_digest,
                        canonical_json_bytes(entry).decode("utf-8"),
                    ),
                )

                checkpoint = self._make_checkpoint(con, seq, e_digest)
                con.execute(
                    "INSERT INTO journal_checkpoints(seq, checkpoint_json) VALUES(?, ?)",
                    (seq, canonical_json_bytes(checkpoint).decode("utf-8")),
                )
                con.commit()
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise
        return entry

    def _executor_id_from_signed_intent(
        self, con: sqlite3.Connection, operation_id: str
    ) -> str:
        """Resolve the RESULT's executor_id from the SIGNED INTENT entry_json.

        The unsigned ``executor_id`` helper column is never trusted: mutating it
        in SQLite cannot change what a RESULT inherits. Candidate rows are still
        located by indexed helper columns, but the value is read from the signed
        ``entry_json`` and the located entry is re-verified (field set, digests,
        signature and operation_id binding) before its executor_id is used.
        A tampered or unsigned INTENT therefore fails closed here.
        """
        rows = con.execute(
            "SELECT seq, entry_json FROM journal_entries "
            "WHERE operation_id=? AND phase='INTENT' ORDER BY seq ASC",
            (operation_id,),
        ).fetchall()
        for row in rows:
            entry = json.loads(row["entry_json"])
            self._verify_entry(entry)  # fail closed on any tampered signed object
            if entry["operation_id"] == operation_id and entry["phase"] == "INTENT":
                return entry["executor_id"]
        raise JournalError("cannot inherit executor_id: no valid signed INTENT for operation_id")

    def _make_checkpoint(
        self, con: sqlite3.Connection, seq: int, journal_head_digest: str
    ) -> dict[str, Any]:
        unsigned = {"seq": seq, "journal_head_digest": journal_head_digest}
        cp_digest = _checkpoint_digest(unsigned)
        return {
            **unsigned,
            "checkpoint_digest": cp_digest,
            "checkpoint_signature": _sign(
                self._signing_key, _checkpoint_sign_message(cp_digest)
            ),
        }

    @staticmethod
    def _entry_digest_from_json(entry_json: str) -> str:
        return json.loads(entry_json)["entry_digest"]

    # -- read paths (verify on read) --------------------------------------------
    def head(self) -> dict[str, Any]:
        with self._db() as con:
            row = con.execute(
                "SELECT checkpoint_json FROM journal_checkpoints ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        if row is None:
            raise JournalError("journal is empty: no head checkpoint")
        checkpoint = json.loads(row["checkpoint_json"])
        self._verify_checkpoint(checkpoint)
        return checkpoint

    def checkpoint_at(self, seq: int) -> dict[str, Any]:
        with self._db() as con:
            row = con.execute(
                "SELECT checkpoint_json FROM journal_checkpoints WHERE seq=?", (seq,)
            ).fetchone()
        if row is None:
            raise JournalError(f"no checkpoint at seq {seq}")
        checkpoint = json.loads(row["checkpoint_json"])
        self._verify_checkpoint(checkpoint)
        return checkpoint

    def entries_from(self, seq: int) -> list[dict[str, Any]]:
        with self._db() as con:
            rows = con.execute(
                "SELECT entry_json FROM journal_entries WHERE seq>=? ORDER BY seq ASC", (seq,)
            ).fetchall()
        entries = [json.loads(r["entry_json"]) for r in rows]
        for entry in entries:
            self._verify_entry(entry)
        return entries

    # -- verification -----------------------------------------------------------
    def _verify_checkpoint(self, checkpoint: Mapping[str, Any]) -> None:
        if set(checkpoint) != _CHECKPOINT_FIELDS:
            raise JournalIntegrityError("checkpoint field set mismatch")
        if isinstance(checkpoint["seq"], bool) or not isinstance(checkpoint["seq"], int):
            raise JournalIntegrityError("checkpoint seq must be an int")
        if not enc.is_sha256(checkpoint["journal_head_digest"]):
            raise JournalIntegrityError("checkpoint journal_head_digest is not sha256")
        expected = _checkpoint_digest(_checkpoint_unsigned(checkpoint))
        if expected != checkpoint["checkpoint_digest"]:
            raise JournalIntegrityError("checkpoint_digest mismatch")
        _verify(
            self._verify_key,
            checkpoint["checkpoint_signature"],
            _checkpoint_sign_message(expected),
        )

    def _verify_entry(self, entry: Mapping[str, Any]) -> None:
        if set(entry) != _ENTRY_FIELDS:
            raise JournalIntegrityError("journal entry field set mismatch")
        if isinstance(entry["seq"], bool) or not isinstance(entry["seq"], int):
            raise JournalIntegrityError("entry seq must be an int")
        if entry["phase"] not in _VALID_PHASES:
            raise JournalIntegrityError("entry phase is invalid")
        if not enc.is_sha256(entry["prev_digest"]) or not enc.is_sha256(entry["payload_digest"]):
            raise JournalIntegrityError("entry digest fields are not sha256")

        # E1.9-A.1 fix #1 (read path, independent of append): the outer
        # operation_id is part of the signed unsigned_entry, and the envelope
        # carries its own operation_id inside payload_digest. Both must match,
        # otherwise a validly signed entry can still have ambiguous identity.
        env = entry["envelope"]
        if not isinstance(env, Mapping) or env.get("operation_id") != entry["operation_id"]:
            raise JournalIntegrityError("entry operation_id not bound to envelope operation_id")

        # envelope -> payload_digest (E1.8 §5.2 recovery completeness check)
        if entry["phase"] == "INTENT":
            expected_payload = _intent_payload_digest(entry["envelope"])
        else:
            expected_payload = _result_payload_digest(entry["envelope"])
        if expected_payload != entry["payload_digest"]:
            raise JournalIntegrityError("payload_digest mismatch with envelope")

        expected_entry = _entry_digest(_entry_unsigned(entry))
        if expected_entry != entry["entry_digest"]:
            raise JournalIntegrityError("entry_digest mismatch")
        _verify(
            self._verify_key,
            entry["entry_signature"],
            _entry_sign_message(expected_entry),
        )

    def verify_integrity(self) -> int:
        """Verify the ENTIRE log prefix; return the number of entries.

        Checks, in order: unsigned helper columns == signed entry_json, seq
        continuity from 1, prev_digest linkage (including genesis), per-entry
        digest/signature/envelope (+ operation_id binding), INTENT-before-RESULT,
        one checkpoint per seq, checkpoint digest/signature, and checkpoint
        -> entry_digest head binding. Any failure raises JournalIntegrityError.
        """
        with self._db() as con:
            entry_rows = con.execute(
                "SELECT seq, operation_id, phase, executor_id, entry_digest, entry_json "
                "FROM journal_entries ORDER BY seq ASC"
            ).fetchall()
            cp_rows = con.execute(
                "SELECT checkpoint_json FROM journal_checkpoints ORDER BY seq ASC"
            ).fetchall()

        entries = [json.loads(r["entry_json"]) for r in entry_rows]
        checkpoints = [json.loads(r["checkpoint_json"]) for r in cp_rows]

        # E1.9-A.1 fix #2: the unsigned SQLite helper columns are indexes only.
        # They MUST agree with the signed entry_json, otherwise an attacker could
        # rewrite executor_id/operation_id/phase in the helper column to steer
        # the lookup while the signed object still verifies. Strictly cross-check
        # them here so any such divergence fails closed.
        for row, entry in zip(entry_rows, entries):
            for col in ("seq", "operation_id", "phase", "executor_id", "entry_digest"):
                if row[col] != entry[col]:
                    raise JournalIntegrityError(
                        f"unsigned helper column {col} diverges from signed entry at seq {row['seq']}"
                    )

        if not entries:
            if checkpoints:
                raise JournalIntegrityError("checkpoints exist but journal has no entries")
            return 0

        seen_intents: set[str] = set()
        prev = GENESIS_PREV_DIGEST
        for expected_seq, entry in enumerate(entries, start=1):
            if entry["seq"] != expected_seq:
                raise JournalIntegrityError(f"seq discontinuity at position {expected_seq}")
            if entry["prev_digest"] != prev:
                raise JournalIntegrityError(f"prev_digest linkage broken at seq {expected_seq}")
            self._verify_entry(entry)
            if entry["phase"] == "INTENT":
                seen_intents.add(entry["operation_id"])
            elif entry["operation_id"] not in seen_intents:
                raise JournalIntegrityError("RESULT appears before its INTENT")
            prev = entry["entry_digest"]

        if len(checkpoints) != len(entries):
            raise JournalIntegrityError("checkpoint count does not match entry count")
        head_by_seq = {e["seq"]: e["entry_digest"] for e in entries}
        for expected_seq, checkpoint in enumerate(checkpoints, start=1):
            if checkpoint["seq"] != expected_seq:
                raise JournalIntegrityError(f"checkpoint seq discontinuity at {expected_seq}")
            self._verify_checkpoint(checkpoint)
            if checkpoint["journal_head_digest"] != head_by_seq.get(expected_seq):
                raise JournalIntegrityError(
                    f"checkpoint at seq {expected_seq} not bound to that entry_digest"
                )
        return len(entries)


__all__ = [
    "DOMAIN_INTENT",
    "DOMAIN_RESULT_ENVELOPE",
    "DOMAIN_ENTRY",
    "DOMAIN_ENTRY_SIGN",
    "DOMAIN_CHECKPOINT",
    "DOMAIN_CHECKPOINT_SIGN",
    "DOMAIN_GENESIS",
    "GENESIS_PREV_DIGEST",
    "JournalError",
    "JournalIntegrityError",
    "AuthorityJournal",
]
