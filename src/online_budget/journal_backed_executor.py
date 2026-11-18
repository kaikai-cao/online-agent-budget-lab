"""E1.9-C orchestration layer: bind the independent Journal Service to the
existing Executor execution chain (C1 IPC / C2 ordering / C3 recovery).

Design boundaries (E0 §9 — do not weaken):
  * This module is OUTSIDE the frozen core.  It does NOT modify journal.py,
    journal_service.py, executor.py::execute_e1, or any e1_* gate.  It calls
    them through their existing public interfaces.
  * The four pre-dispatch gates + dispatch + Receipt signing + local execution
    persistence remain entirely inside ``TrustedToolExecutor.execute_e1()``.
    This layer only wraps it: INTENT before dispatch, RESULT after, and recovery
    from the authoritative Journal when local state is behind.
  * Recovery returns the ORIGINAL signed Receipt from the Journal's RESULT
    envelope.  It verifies signature + binding + envelope digest, and NEVER
    calls make_receipt / re-signs (E0 §9.2 constraint 6).
  * Local sync state (last_applied_seq / last_checkpoint_digest) lives in a
    SEPARATE SQLite file owned by this layer, not in the frozen ExecutionStore.
  * No G1b / exactly-once / execution-truth claims.  Journal is a trusted
    recorder, not an execution-proof oracle (E0 §7-8).

A1 shared-store serialization is provided by a `BEGIN IMMEDIATE` write lock on
the sync-state DB around the whole INTENT→dispatch→RESULT→local-update sequence
when multiple Executor instances share that sync DB (E1.9 plan §2.4).  This is
shared-store serialization only, NOT G1b.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
from typing import Any, Callable, Mapping
import dataclasses

from . import execution_receipts as er
from .canonical import canonical_json_bytes
from .e1_encoding import canonical_digest
from .journal_client import JournalClient, JournalClientError

# Domain tag is the actually frozen one (journal.py DOMAIN_RESULT_ENVELOPE).
RESULT_ENVELOPE_DOMAIN = "e1-result-envelope-v1"


class E1CFailClosed(RuntimeError):
    """Any condition that must stop execution without dispatch."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class E1CStateDiverged(E1CFailClosed):
    def __init__(self, message: str) -> None:
        super().__init__("LOCAL_STATE_DIVERGED", message)


class E1CRollbackSuspected(E1CFailClosed):
    def __init__(self, message: str) -> None:
        super().__init__("ROLLBACK_SUSPECTED", message)


class E1CIntegrityFailure(E1CFailClosed):
    def __init__(self, message: str) -> None:
        super().__init__("JOURNAL_INTEGRITY_FAILURE", message)


class E1CReceiptInvalid(E1CFailClosed):
    def __init__(self, message: str) -> None:
        super().__init__("RECOVERED_RECEIPT_INVALID", message)


# ---------------------------------------------------------------------------
# Local sync state (separate DB; frozen ExecutionStore untouched)
# ---------------------------------------------------------------------------


class E1CLocalState:
    """Durable local sync state for E1.9-C.

    Tables:
      e1c_status(operation_id PK, binding_digest, result_json, receipt_json,
                 last_applied_seq, last_checkpoint_digest)
      e1c_meta(k PK, v) -- stores global last_applied_seq / last_checkpoint_digest.
    """

    def __init__(self, database_path: str | Path) -> None:
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as con:
            con.execute(
                "CREATE TABLE IF NOT EXISTS e1c_status ("
                "operation_id TEXT PRIMARY KEY, binding_digest TEXT NOT NULL, "
                "result_json TEXT NOT NULL, receipt_json TEXT NOT NULL, "
                "last_applied_seq INTEGER NOT NULL, last_checkpoint_digest TEXT NOT NULL)"
            )
            con.execute("CREATE TABLE IF NOT EXISTS e1c_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)")

    def _connect(self):
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

    @contextmanager
    def write_lock(self):
        """A1: BEGIN IMMEDIATE held until commit/rollback, covering dispatch."""
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                yield con
            except BaseException:
                con.rollback()
                raise
            else:
                con.commit()

    # -- per-operation status ---------------------------------------------------
    def get_status(self, con, operation_id: str) -> dict[str, Any] | None:
        row = con.execute("SELECT * FROM e1c_status WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            return None
        return {
            "operation_id": row["operation_id"],
            "binding_digest": row["binding_digest"],
            "result": json.loads(row["result_json"]),
            "receipt": json.loads(row["receipt_json"]),
            "last_applied_seq": int(row["last_applied_seq"]),
            "last_checkpoint_digest": row["last_checkpoint_digest"],
        }

    def put_status(self, con, *, operation_id: str, binding_digest: str, result: Any,
                   receipt: Mapping[str, Any], last_applied_seq: int,
                   last_checkpoint_digest: str) -> None:
        existing = self.get_status(con, operation_id)
        receipt_json = canonical_json_bytes(dict(receipt)).decode("utf-8")
        result_json = canonical_json_bytes(result).decode("utf-8")
        if existing is not None:
            if (existing["binding_digest"] != binding_digest
                    or existing["receipt"] != dict(receipt)):
                raise E1CFailClosed(
                    "LOCAL_STATE_CONFLICT",
                    "operation_id already bound to a different result/receipt",
                )
            return
        con.execute(
            "INSERT INTO e1c_status(operation_id,binding_digest,result_json,receipt_json,"
            "last_applied_seq,last_checkpoint_digest) VALUES(?,?,?,?,?,?)",
            (operation_id, binding_digest, result_json, receipt_json,
             last_applied_seq, last_checkpoint_digest),
        )

    # -- global sync cursor -----------------------------------------------------
    def get_sync(self, con) -> dict[str, Any]:
        rows = {r["k"]: r["v"] for r in con.execute("SELECT k,v FROM e1c_meta").fetchall()}
        seq = int(rows.get("last_applied_seq", "0"))
        digest = rows.get("last_checkpoint_digest", "")
        return {"last_applied_seq": seq, "last_checkpoint_digest": digest}

    def set_sync(self, con, *, last_applied_seq: int, last_checkpoint_digest: str) -> None:
        con.execute(
            "INSERT INTO e1c_meta(k,v) VALUES('last_applied_seq',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (str(last_applied_seq),),
        )
        con.execute(
            "INSERT INTO e1c_meta(k,v) VALUES('last_checkpoint_digest',?) "
            "ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (last_checkpoint_digest,),
        )


# ---------------------------------------------------------------------------
# G2 three-state judgement (E1.8 §7.4)
# ---------------------------------------------------------------------------


def judge_g2_state(client: JournalClient, local_seq: int, local_digest: str) -> str:
    """Return LOCAL_STATE_BEHIND / LOCAL_STATE_DIVERGED / ROLLBACK_SUSPECTED / OK.

    Comparison object = the historical checkpoint at ``local_seq`` vs the
    authoritative checkpoint at the SAME seq (NOT the latest head).  E1.8 §7.4.
    """
    if local_seq == 0:
        return "OK"  # virgin local state; nothing to compare
    try:
        head = client.get_head()
    except JournalClientError as exc:
        if exc.code == "EMPTY_JOURNAL":
            # Journal has no head but local claims applied seq>0: loss/rollback
            # of authoritative history -> cannot confirm -> fail closed.
            return "ROLLBACK_SUSPECTED"
        raise
    head_seq = int(head["seq"])
    if local_seq > head_seq:
        # Local cursor ahead of authority: no same-seq evidence to compare.
        return "ROLLBACK_SUSPECTED"
    cp = client.get_checkpoint(seq=local_seq)
    if cp is None:
        # Authority has no checkpoint at the local seq -> cannot verify prefix.
        return "ROLLBACK_SUSPECTED"
    auth_digest = cp.get("checkpoint_digest")
    if not isinstance(auth_digest, str):
        return "ROLLBACK_SUSPECTED"
    if auth_digest != local_digest:
        return "LOCAL_STATE_DIVERGED"
    if local_seq < head_seq:
        return "LOCAL_STATE_BEHIND"
    return "OK"


# ---------------------------------------------------------------------------
# Recovery: return the ORIGINAL receipt, never rebuild (E0 §9.2 / E1.8 §5.2)
# ---------------------------------------------------------------------------


def recover_result_from_entry(
    *, entry: Mapping[str, Any], operation_id: str, binding_digest: str,
    executor_public_key, expect_result: Any | None = None,
) -> dict[str, Any]:
    """Validate a signed RESULT entry and extract (result, original_receipt).

    Checks: entry phase, operation_id, envelope digest recomputation, receipt
    signature + field bindings, B-F1 result<->receipt binding.  Returns the
    original receipt object verbatim.
    """
    if entry.get("phase") != "RESULT":
        raise E1CReceiptInvalid("entry is not a RESULT entry")
    if entry.get("operation_id") != operation_id:
        raise E1CReceiptInvalid("entry operation_id mismatch")
    env = entry.get("envelope")
    if not isinstance(env, Mapping):
        raise E1CReceiptInvalid("RESULT entry has no envelope")
    if set(env) != {"operation_id", "binding_digest", "result", "execution_receipt"}:
        raise E1CReceiptInvalid("RESULT envelope field set mismatch")
    if env.get("operation_id") != operation_id:
        raise E1CReceiptInvalid("envelope operation_id mismatch")
    if env.get("binding_digest") != binding_digest:
        raise E1CReceiptInvalid("envelope binding_digest mismatch")
    # Recompute the frozen envelope digest against the SIGNED entry digest object.
    expected_payload_digest = canonical_digest(RESULT_ENVELOPE_DOMAIN, dict(env))
    if entry.get("payload_digest") != expected_payload_digest:
        raise E1CReceiptInvalid("envelope digest recomputation mismatch")
    receipt = env.get("execution_receipt")
    verified = er.verify_execution_receipt(
        receipt, executor_public_key,
        expected={"operation_id": operation_id, "binding_digest": binding_digest},
    )
    if not verified:
        raise E1CReceiptInvalid("original Receipt signature/binding verification failed")
    payload = receipt["payload"] if isinstance(receipt, dict) and "payload" in receipt else None
    if payload is None:
        raise E1CReceiptInvalid("original Receipt has no payload")
    if payload.get("result") != env.get("result"):
        raise E1CReceiptInvalid("Receipt result != envelope result (B-F1)")
    if expect_result is not None and env.get("result") != expect_result:
        raise E1CReceiptInvalid("recovered result differs from requested result")
    return {"result": env["result"], "receipt": dict(receipt)}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class JournalBackedExecutor:
    """Wrap TrustedToolExecutor.execute_e1 with Journal INTENT/RESULT + recovery."""

    def __init__(self, *, executor: Any, client: JournalClient, state: E1CLocalState,
                 executor_public_key) -> None:
        self._executor = executor
        self._client = client
        self._state = state
        self._pubkey = executor_public_key

    @staticmethod
    def binding_digest_from_pending(pending: Any) -> str:
        raw = getattr(pending, "binding", None)
        if not isinstance(raw, Mapping) or "binding_digest" not in raw:
            # PendingExecution.binding is the ToolCallBinding payload (may or may
            # not carry binding_digest).  Derive it from the signing helper.
            from .tool_binding import ToolCallBinding
            fields = {f.name for f in dataclasses.fields(ToolCallBinding)} - {"binding_digest"}
            if not isinstance(raw, Mapping) or set(raw) != fields:
                raise E1CFailClosed("BAD_PENDING_BINDING", "PendingExecution binding malformed")
            return ToolCallBinding(**dict(raw)).binding_digest
        return str(raw["binding_digest"])

    def execute_with_journal(
        self, *, pending_execution: Any, operation_id: str, binding_digest: str,
        dispatch_args: Mapping[str, Any], on_result: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        enforce_integrity: bool = True,
    ) -> dict[str, Any]:
        """Run the full INTENT→dispatch→RESULT→local chain, or recover.

        ``dispatch_args`` are forwarded verbatim to ``executor.execute_e1``.
        ``on_result(receipt)`` may post-process a newly produced receipt but MUST
        return the original receipt unchanged for the RESULT envelope; by
        default the original receipt is used directly.
        """
        if not isinstance(operation_id, str) or not operation_id:
            raise E1CFailClosed("BAD_OPERATION_ID", "operation_id must be non-empty")
        if not isinstance(binding_digest, str) or not binding_digest:
            raise E1CFailClosed("BAD_BINDING_DIGEST", "binding_digest must be non-empty")

        with self._state.write_lock() as con:
            # (0) Journal integrity gate — fail closed on any inconsistency.
            if enforce_integrity:
                try:
                    self._client.verify_integrity()
                except JournalClientError as exc:
                    raise E1CIntegrityFailure(f"{exc.code}: {exc.message}") from exc

            # (1) Local idempotency first.
            local = self._state.get_status(con, operation_id)
            if local is not None:
                if local["binding_digest"] != binding_digest:
                    raise E1CFailClosed(
                        "BINDING_CONFLICT", "operation_id bound to a different binding_digest"
                    )
                return dict(local["receipt"])

            # (2) G2 three-state judgement against the authoritative Journal.
            sync = self._state.get_sync(con)
            g2 = judge_g2_state(self._client, sync["last_applied_seq"], sync["last_checkpoint_digest"])
            if g2 == "LOCAL_STATE_DIVERGED":
                raise E1CStateDiverged("local checkpoint digest differs from authoritative same-seq checkpoint")
            if g2 == "ROLLBACK_SUSPECTED":
                raise E1CRollbackSuspected("insufficient evidence; refusing to dispatch")

            # (3) RESULT-already-in-Journal -> recover (window 2).  MUST run
            #     before any dispatch decision (E1.9 plan §2.4).
            result_entry = self._client.get_entry(operation_id=operation_id, phase="RESULT")
            if result_entry is not None:
                recovered = recover_result_from_entry(
                    entry=result_entry, operation_id=operation_id,
                    binding_digest=binding_digest, executor_public_key=self._pubkey,
                )
                head = self._client.get_head()
                self._state.put_status(
                    con, operation_id=operation_id, binding_digest=binding_digest,
                    result=recovered["result"], receipt=recovered["receipt"],
                    last_applied_seq=int(head["seq"]),
                    last_checkpoint_digest=str(head["checkpoint_digest"]),
                )
                self._state.set_sync(
                    con, last_applied_seq=int(head["seq"]),
                    last_checkpoint_digest=str(head["checkpoint_digest"]),
                )
                return dict(recovered["receipt"])  # original object, no re-sign

            # (4) Append INTENT BEFORE dispatch (C2).  The claim executor_id is
            #     authorized by the service against OS identity (no client trust).
            try:
                intent_res = self._client.append_intent(
                    operation_id=operation_id, binding_digest=binding_digest
                )
            except JournalClientError as exc:
                raise E1CFailClosed(f"INTENT_{exc.code}", exc.message) from exc
            intent_seq = int(intent_res["entry"]["seq"])

            # (5) Execute via the frozen four-gate chain.  No hook into it; the
            #     dispatch + Receipt signing + local execution persist happen
            #     entirely inside execute_e1().
            receipt = self._executor.execute_e1(
                pending_execution=pending_execution, **dict(dispatch_args)
            )
            if not isinstance(receipt, Mapping) or "payload" not in receipt:
                raise E1CFailClosed("BAD_RECEIPT", "execute_e1 returned no original Receipt")
            # The returned object is the ORIGINAL signed receipt; never rebuild.
            receipt_dict = dict(receipt)
            result_value = receipt_dict["payload"].get("result")

            # (6) Append RESULT bound to the original receipt.
            try:
                result_res = self._client.append_result(
                    operation_id=operation_id, binding_digest=binding_digest,
                    result_value=result_value, execution_receipt=receipt_dict,
                )
            except JournalClientError as exc:
                raise E1CFailClosed(f"RESULT_{exc.code}", exc.message) from exc

            # (7) Advance local state AFTER authoritative RESULT (Saga order).
            head = self._client.get_head()
            head_seq = int(head["seq"])
            head_digest = str(head["checkpoint_digest"])
            if head_seq <= intent_seq:
                raise E1CIntegrityFailure("head did not advance past INTENT after RESULT")
            self._state.put_status(
                con, operation_id=operation_id, binding_digest=binding_digest,
                result=result_value, receipt=receipt_dict,
                last_applied_seq=head_seq, last_checkpoint_digest=head_digest,
            )
            self._state.set_sync(con, last_applied_seq=head_seq, last_checkpoint_digest=head_digest)
            return receipt_dict
