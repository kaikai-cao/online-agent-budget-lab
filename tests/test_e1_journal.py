"""E1.9-A -- Journal Foundation acceptance tests (J01-J10).

Scope: the standalone authoritative Journal component only. These tests do NOT
touch executor.py / execution_store.py execution flow, the E1.5 gates, or any
D10/D11 credential. They verify the Journal core: global seq, prev_digest chain,
per-entry and per-checkpoint Ed25519 signatures, historical checkpoints, restart
recovery, and fail-closed integrity checks on tamper / truncation.

Trust-boundary honesty:
  * J06/J07/J08 show the component DETECTS in-place modification of stored log
    or checkpoint bytes (a cryptographic property of the signed hash chain).
  * J10 shows restoring an Executor DB snapshot does not alter the Journal file
    (physical separation only). It does NOT show the Journal itself cannot be
    rolled back by an attacker who can also replace this file. See the module
    docstring and docs/E1_9_A_JOURNAL_FOUNDATION.md.
"""

from __future__ import annotations

from contextlib import closing
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from online_budget.journal import (
    GENESIS_PREV_DIGEST,
    AuthorityJournal,
    JournalError,
    JournalIntegrityError,
)


def _digest(tag: str) -> str:
    return "sha256:" + tag * 64


def _intent(op: str, *, binding: str | None = None, executor: str = "exec-A") -> dict:
    return {
        "operation_id": op,
        "binding_digest": binding or _digest("a"),
        "executor_id": executor,
    }


def _result(op: str, *, binding: str | None = None, value: int = 1) -> dict:
    return {
        "operation_id": op,
        "binding_digest": binding or _digest("a"),
        "result": {"value": value},
        "execution_receipt": {"kind": "receipt", "value": value},
    }


class _JournalCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.key = Ed25519PrivateKey.generate()
        self.journal_path = self.dir / "journal.sqlite3"
        self.journal = self._open()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _open(self, path: Path | None = None) -> AuthorityJournal:
        return AuthorityJournal(
            path or self.journal_path,
            signing_key=self.key,
            verify_key=self.key.public_key(),
        )

    def _append_pair(self, journal: AuthorityJournal, op: str, value: int = 1):
        intent = journal.append(phase="INTENT", operation_id=op, envelope=_intent(op))
        result = journal.append(phase="RESULT", operation_id=op, envelope=_result(op, value=value))
        return intent, result

    # -- J01 -------------------------------------------------------------------
    def test_J01_append_intent_ok_seq_continuous(self):
        e = self.journal.append(phase="INTENT", operation_id="op1", envelope=_intent("op1"))
        self.assertEqual(e["seq"], 1)
        self.assertEqual(e["phase"], "INTENT")
        self.assertEqual(e["prev_digest"], GENESIS_PREV_DIGEST)
        self.assertEqual(e["operation_id"], "op1")
        self.assertEqual(self.journal.verify_integrity(), 1)

    # -- J02 -------------------------------------------------------------------
    def test_J02_append_result_ok_prev_digest_correct(self):
        intent, result = self._append_pair(self.journal, "op2", value=7)
        self.assertEqual(result["seq"], 2)
        self.assertEqual(result["phase"], "RESULT")
        self.assertEqual(result["prev_digest"], intent["entry_digest"])
        # executor_id is inherited from the INTENT (RESULT envelope is the
        # four-field E1.8 §5.2 envelope and does not itself carry executor_id).
        self.assertEqual(result["executor_id"], "exec-A")
        self.assertEqual(self.journal.verify_integrity(), 2)

    # -- J03 -------------------------------------------------------------------
    def test_J03_multiple_entries_chain_verifiable(self):
        for i in range(6):
            self._append_pair(self.journal, f"op{i}", value=i)
        self.assertEqual(self.journal.verify_integrity(), 12)
        entries = self.journal.entries_from(1)
        self.assertEqual([e["seq"] for e in entries], list(range(1, 13)))
        for prev, cur in zip(entries, entries[1:]):
            self.assertEqual(cur["prev_digest"], prev["entry_digest"])

    # -- J04 -------------------------------------------------------------------
    def test_J04_read_historical_checkpoint(self):
        # Each pair writes INTENT then RESULT; checkpoint at seq N binds to the
        # entry at that exact seq. seq1=INTENT(opA), seq2=RESULT(opA).
        i1, r1 = self._append_pair(self.journal, "opA", value=1)
        _, r2 = self._append_pair(self.journal, "opB", value=2)
        cp1 = self.journal.checkpoint_at(1)
        cp2 = self.journal.checkpoint_at(2)
        head = self.journal.head()
        self.assertEqual(cp1["seq"], 1)
        self.assertEqual(cp1["journal_head_digest"], i1["entry_digest"])
        self.assertEqual(cp2["seq"], 2)
        self.assertEqual(cp2["journal_head_digest"], r1["entry_digest"])
        self.assertEqual(head["seq"], 4)
        self.assertEqual(head["journal_head_digest"], r2["entry_digest"])

    # -- J05 -------------------------------------------------------------------
    def test_J05_restart_recovery_signatures_still_valid(self):
        self._append_pair(self.journal, "opR1", value=3)
        self._append_pair(self.journal, "opR2", value=4)
        before = self.journal.head()
        reopened = self._open()  # new instance over the same file
        self.assertEqual(reopened.verify_integrity(), 4)
        self.assertEqual(reopened.head(), before)
        self.assertEqual([e["seq"] for e in reopened.entries_from(1)], [1, 2, 3, 4])

    # -- helpers for tamper tests ---------------------------------------------
    def _overwrite_entry_json(self, seq: int, mutate) -> None:
        with closing(sqlite3.connect(self.journal_path)) as con:
            row = con.execute("SELECT entry_json FROM journal_entries WHERE seq=?", (seq,)).fetchone()
            data = json.loads(row[0])
            mutate(data)
            con.execute(
                "UPDATE journal_entries SET entry_json=? WHERE seq=?",
                (json.dumps(data, sort_keys=True), seq),
            )
            con.commit()

    def _overwrite_checkpoint_json(self, seq: int, mutate) -> None:
        with closing(sqlite3.connect(self.journal_path)) as con:
            row = con.execute(
                "SELECT checkpoint_json FROM journal_checkpoints WHERE seq=?", (seq,)
            ).fetchone()
            data = json.loads(row[0])
            mutate(data)
            con.execute(
                "UPDATE journal_checkpoints SET checkpoint_json=? WHERE seq=?",
                (json.dumps(data, sort_keys=True), seq),
            )
            con.commit()

    # -- J06 -------------------------------------------------------------------
    def test_J06_modified_entry_fails_verification(self):
        self._append_pair(self.journal, "opM", value=9)
        # Tamper stored payload without recomputing digests/signature.
        self._overwrite_entry_json(1, lambda d: d["envelope"].__setitem__("executor_id", "attacker"))
        reopened = self._open()
        with self.assertRaises(JournalIntegrityError):
            reopened.verify_integrity()

    # -- J07 -------------------------------------------------------------------
    def test_J07_modified_checkpoint_fails_verification(self):
        self._append_pair(self.journal, "opC", value=5)
        self._overwrite_checkpoint_json(2, lambda d: d.__setitem__("journal_head_digest", _digest("b")))
        reopened = self._open()
        with self.assertRaises(JournalIntegrityError):
            reopened.checkpoint_at(2)
        with self.assertRaises(JournalIntegrityError):
            reopened.verify_integrity()

    # -- J08 -------------------------------------------------------------------
    def test_J08_deleted_middle_entry_detected(self):
        self._append_pair(self.journal, "opD1", value=1)
        self._append_pair(self.journal, "opD2", value=2)
        with closing(sqlite3.connect(self.journal_path)) as con:
            con.execute("DELETE FROM journal_entries WHERE seq=2")
            con.execute("DELETE FROM journal_checkpoints WHERE seq=2")
            con.commit()
        reopened = self._open()
        with self.assertRaises(JournalIntegrityError):
            reopened.verify_integrity()

    # -- J09 -------------------------------------------------------------------
    def test_J09_concurrent_append_global_seq_unique_and_gapless(self):
        threads = 8
        per_thread = 5
        errors: list[BaseException] = []
        barrier = threading.Barrier(threads)

        def worker(idx: int):
            try:
                local = self._open()
                barrier.wait()
                for n in range(per_thread):
                    op = f"op-{idx}-{n}"
                    local.append(phase="INTENT", operation_id=op, envelope=_intent(op))
                    local.append(phase="RESULT", operation_id=op, envelope=_result(op, value=n))
            except BaseException as exc:  # pragma: no cover - captured for assertion
                errors.append(exc)

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(threads)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()

        self.assertEqual(errors, [])
        total = threads * per_thread * 2
        self.assertEqual(self.journal.verify_integrity(), total)
        seqs = [e["seq"] for e in self.journal.entries_from(1)]
        self.assertEqual(seqs, list(range(1, total + 1)))

    # -- J10 -------------------------------------------------------------------
    def test_J10_restore_executor_snapshot_leaves_journal_unchanged(self):
        # A separate, ordinary SQLite file stands in for the Executor DB.
        executor_db = self.dir / "executor.sqlite3"
        with closing(sqlite3.connect(executor_db)) as con:
            con.execute("CREATE TABLE IF NOT EXISTS executions (operation_id TEXT PRIMARY KEY, state TEXT)")
            con.execute("INSERT INTO executions VALUES('opX','SUCCEEDED')")
            con.commit()
        snapshot = executor_db.read_bytes()

        self._append_pair(self.journal, "opJ10", value=42)
        head_before = self.journal.head()
        entries_before = self.journal.entries_from(1)
        journal_bytes_before = self.journal_path.read_bytes()

        # Mutate and then roll back ONLY the Executor DB file.
        with closing(sqlite3.connect(executor_db)) as con:
            con.execute("UPDATE executions SET state='FAILED' WHERE operation_id='opX'")
            con.commit()
        executor_db.write_bytes(snapshot)

        self.assertEqual(self.journal.head(), head_before)
        self.assertEqual(self.journal.entries_from(1), entries_before)
        self.assertEqual(self.journal_path.read_bytes(), journal_bytes_before)
        self.assertEqual(self.journal.verify_integrity(), 2)
        # NOTE: this proves physical separation only, NOT Journal anti-rollback.

    # -- additional negative ordering checks ----------------------------------
    def test_result_without_prior_intent_rejected(self):
        with self.assertRaises(JournalError):
            self.journal.append(phase="RESULT", operation_id="orphan", envelope=_result("orphan"))

    def test_bad_intent_envelope_shape_rejected(self):
        with self.assertRaises(JournalError):
            self.journal.append(
                phase="INTENT",
                operation_id="bad",
                envelope={"operation_id": "bad", "binding_digest": _digest("a")},
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
