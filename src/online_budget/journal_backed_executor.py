"""E1.9-C orchestration layer: bind the independent Journal Service to the
existing Executor execution chain (C1 IPC / C2 ordering / C3 recovery).

E1.9-C.1 authoritative-ordering correction (baseline 309e465):
  * A1 write lock is now on the REAL ExecutionStore DB via
    ``ExecutionStore.write_transaction()`` -- NOT on a separate sync DB.  The
    BEGIN IMMEDIATE spans dedup / Journal query / G2 / INTENT / dispatch /
    RESULT / local commit.  The E1CLocalState cursor tables are created in the
    SAME DB file, so the single transaction covers them too (C2).
  * Journal RESULT is appended via a ``before_store_commit`` callback that runs
    INSIDE execute_e1's local transaction -- AFTER the original Receipt is
    signed, BEFORE the local row is inserted/committed.  Thus RESULT is always
    authoritative before the ExecutionStore commit (C1).  Local commit failure
    leaves a recoverable RESULT; retry restores the ORIGINAL receipt.
  * G2 LOCAL_STATE_BEHIND is no longer a no-op: it replays seq-by-seq with
    prev_digest / checkpoint / INTENT-RESULT validation and recovers original
    receipts, with NO dispatch until caught up (C3).
  * Request identity (operation_id + binding_digest) is re-derived from the
    pending binding PAYLOAD and cross-checked before any INTENT (C4).

Design boundaries (E0 §9 — do not weaken):
  * The four pre-dispatch gates, dispatch, Receipt signing and one-shot
    capability inside ``TrustedToolExecutor.execute_e1()`` are UNCHANGED.  Only
    optional keyword arguments (``store_con`` / ``before_store_commit``) were
    added to thread the A1 connection and the RESULT callback through; no gate,
    credential format or signature protocol was altered.
  * Recovery returns the ORIGINAL signed Receipt.  It verifies signature +
    binding + envelope digest and NEVER re-signs (E0 §9.2 constraint 6).
  * Cross-store atomicity between the Journal and the ExecutionStore is NOT
    claimed: a RESULT-then-local-commit failure is a Saga window (E1.9 §2.4).
  * No G1b / exactly-once / execution-truth claims.  Journal is a trusted
    recorder, not an execution-proof oracle (E0 §7-8).
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
# Request identity derivation (E1.9-C.1 C4)
# ---------------------------------------------------------------------------


def derive_request_identity(pending: Any) -> tuple[str, str, Any]:
    """Re-derive (operation_id, binding_digest, ToolCallBinding) from the
    pending execution's binding PAYLOAD -- never trust any caller-supplied or
    pending-embedded ``binding_digest`` claim.

    This mirrors the frozen ``execute_e1`` Gate 1a exactly: the binding payload
    must be the exact 14-field set of ToolCallBinding.payload(), validate(), and
    the digest is computed from those fields.  Any mismatch/missing field fails
    closed BEFORE any Journal INTENT is appended (E1.9-C.1 C4).
    """
    from .tool_binding import ToolCallBinding

    raw = getattr(pending, "binding", None)
    fields = {f.name for f in dataclasses.fields(ToolCallBinding)} - {"binding_digest"}
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise E1CFailClosed("BAD_PENDING_BINDING", "PendingExecution binding payload malformed")
    try:
        binding = ToolCallBinding(**dict(raw))
        binding.validate()
    except (TypeError, ValueError) as exc:
        raise E1CFailClosed("BAD_PENDING_BINDING", f"PendingExecution binding invalid: {exc}") from exc
    return binding.operation_id, binding.binding_digest, binding


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class JournalBackedExecutor:
    """Wrap TrustedToolExecutor.execute_e1 with Journal INTENT/RESULT + recovery.

    E1.9-C.1 authoritative ordering (C1/C2): the A1 write lock is on the REAL
    ``ExecutionStore`` DB (``store.write_transaction()``), held from dedup /
    Journal query through INTENT, dispatch, RESULT and the local commit.  The
    Journal RESULT is appended via a ``before_store_commit`` callback that runs
    INSIDE execute_e1's local transaction, AFTER the original Receipt is signed
    but BEFORE the local row is inserted/committed.  If the local commit fails,
    the RESULT is already authoritative and recovery restores the ORIGINAL
    receipt without a second dispatch or any re-signing.

    Cross-store atomicity is explicitly NOT claimed (E1.9 plan §2.4): a failure
    between RESULT append and local commit is a Saga window, recovered on retry.
    """

    def __init__(self, *, executor: Any, client: JournalClient, store: Any,
                 executor_public_key, state: E1CLocalState | None = None) -> None:
        self._executor = executor
        self._client = client
        self._store = store
        # A1 correctness requires the sync cursor to live in the SAME database
        # as the ExecutionStore so write_transaction() covers it.  Fail closed
        # on any attempt to use a separate sync DB (the old P0-3 defect).
        store_path = Path(getattr(store, "path", "")).resolve()
        if state is not None and Path(state.path).resolve() != store_path:
            raise E1CFailClosed(
                "A1_DB_MISMATCH",
                "E1CLocalState must share the ExecutionStore database (A1 boundary)",
            )
        self._state = state if state is not None else E1CLocalState(store_path)
        self._pubkey = executor_public_key

    @staticmethod
    def binding_digest_from_pending(pending: Any) -> str:
        return derive_request_identity(pending)[1]

    def _append_result_hook(self, *, operation_id: str, binding_digest: str,
                            receipt: Mapping[str, Any]) -> None:
        """before_store_commit: persist Journal RESULT before local commit."""
        result_value = receipt["payload"].get("result")
        try:
            self._client.append_result(
                operation_id=operation_id, binding_digest=binding_digest,
                result_value=result_value, execution_receipt=dict(receipt),
            )
        except JournalClientError as exc:
            raise E1CFailClosed(f"RESULT_{exc.code}", exc.message) from exc

    def _replay_behind(self, *, con, local_seq: int, head: Mapping[str, Any]) -> None:
        """E1.9-C.1 C3: replay last_applied_seq+1..head with full validation.

        Verifies seq continuity, prev_digest linkage, the checkpoint at each seq
        bound to that entry's entry_digest, INTENT-before-RESULT, and the RESULT
        envelope/signature.  Recovers the ORIGINAL result+receipt of every RESULT
        into the local sync state.  NO dispatch occurs here.  Any divergence
        fails closed.  On success the sync cursor is advanced to head.
        """
        head_seq = int(head["seq"])
        if local_seq >= head_seq:
            return
        base_cp = self._client.get_checkpoint(seq=local_seq)
        if base_cp is None:
            raise E1CStateDiverged("no authoritative checkpoint at local cursor during replay")
        prev_digest = str(base_cp["journal_head_digest"])
        entries = self._client.get_entries_from(seq=local_seq + 1)
        expected_seq = local_seq + 1
        seen_intents: set[str] = set()
        for entry in entries:
            if int(entry["seq"]) != expected_seq:
                raise E1CStateDiverged(f"replay seq discontinuity at {expected_seq}")
            if str(entry.get("prev_digest")) != prev_digest:
                raise E1CStateDiverged(f"replay prev_digest linkage broken at seq {expected_seq}")
            cp = self._client.get_checkpoint(seq=expected_seq)
            if cp is None or str(cp.get("journal_head_digest")) != str(entry.get("entry_digest")):
                raise E1CStateDiverged(f"replay checkpoint/entry digest mismatch at seq {expected_seq}")
            phase = entry.get("phase")
            op = entry.get("operation_id")
            if phase == "INTENT":
                seen_intents.add(op)
            elif phase == "RESULT":
                # Validate INTENT/RESULT correspondence against the AUTHORITATIVE
                # Journal, not just entries seen in this replay window: the local
                # cursor may sit exactly on the op's INTENT (seq < local_seq+1).
                intent_entry = self._client.get_entry(operation_id=op, phase="INTENT")
                if intent_entry is None or int(intent_entry["seq"]) >= expected_seq:
                    raise E1CReceiptInvalid(f"replay RESULT before INTENT at seq {expected_seq}")
                seen_intents.add(op)
                env = entry.get("envelope")
                bd = env.get("binding_digest") if isinstance(env, Mapping) else None
                if not isinstance(bd, str) or not bd:
                    raise E1CReceiptInvalid(f"replay RESULT has no binding_digest at seq {expected_seq}")
                recovered = recover_result_from_entry(
                    entry=entry, operation_id=op, binding_digest=bd,
                    executor_public_key=self._pubkey,
                )
                self._state.put_status(
                    con, operation_id=op, binding_digest=bd,
                    result=recovered["result"], receipt=recovered["receipt"],
                    last_applied_seq=expected_seq,
                    last_checkpoint_digest=str(cp["checkpoint_digest"]),
                )
            else:
                raise E1CStateDiverged(f"unknown phase at seq {expected_seq}")
            prev_digest = str(entry["entry_digest"])
            expected_seq += 1
        if expected_seq - 1 != head_seq:
            raise E1CStateDiverged("replay did not reach authoritative head")
        self._state.set_sync(
            con, last_applied_seq=head_seq,
            last_checkpoint_digest=str(head["checkpoint_digest"]),
        )

    def execute_with_journal(
        self, *, pending_execution: Any, operation_id: str, binding_digest: str,
        dispatch_args: Mapping[str, Any], enforce_integrity: bool = True,
    ) -> dict[str, Any]:
        """Run the full INTENT→dispatch→RESULT→local chain, or recover.

        ``dispatch_args`` are forwarded verbatim to ``executor.execute_e1``.
        The returned receipt is always the ORIGINAL signed object (never rebuilt).
        """
        # (C4) Request identity is re-derived from the pending binding payload
        # and cross-checked BEFORE any INTENT append or dispatch.
        derived_op, derived_bd, binding = derive_request_identity(pending_execution)
        if operation_id != derived_op:
            raise E1CFailClosed("REQUEST_OPERATION_MISMATCH", "caller operation_id differs from pending binding")
        if getattr(pending_execution, "operation_id", derived_op) != derived_op:
            raise E1CFailClosed("PENDING_OPERATION_MISMATCH", "pending.operation_id differs from binding")
        if binding_digest != derived_bd:
            raise E1CFailClosed("REQUEST_BINDING_MISMATCH", "caller binding_digest differs from pending binding")

        # (A1) One write transaction on the REAL ExecutionStore DB spans the
        # entire decision + dispatch + RESULT + local commit (E1.9 plan §2.4).
        with self._store.write_transaction() as con:
            # (0) Journal integrity gate — fail closed on any inconsistency.
            if enforce_integrity:
                try:
                    self._client.verify_integrity()
                except JournalClientError as exc:
                    raise E1CIntegrityFailure(f"{exc.code}: {exc.message}") from exc

            # (1) G2 three-state judgement against the authoritative Journal.
            sync = self._state.get_sync(con)
            g2 = judge_g2_state(self._client, sync["last_applied_seq"], sync["last_checkpoint_digest"])
            if g2 == "LOCAL_STATE_DIVERGED":
                raise E1CStateDiverged("local checkpoint digest differs from authoritative same-seq checkpoint")
            if g2 == "ROLLBACK_SUSPECTED":
                raise E1CRollbackSuspected("insufficient evidence; refusing to dispatch")
            if g2 == "LOCAL_STATE_BEHIND":
                # C3: replay the missing prefix FIRST; no dispatch until caught up.
                self._replay_behind(
                    con=con, local_seq=sync["last_applied_seq"], head=self._client.get_head()
                )

            # (2) Local idempotency (inside the A1 transaction).
            local = self._state.get_status(con, operation_id)
            if local is not None:
                if local["binding_digest"] != binding_digest:
                    raise E1CFailClosed(
                        "BINDING_CONFLICT", "operation_id bound to a different binding_digest"
                    )
                return dict(local["receipt"])

            # (3) RESULT-already-in-Journal -> recover (window 3).  Restore the
            #     ORIGINAL result + receipt into BOTH the real ExecutionStore and
            #     the sync state; never re-sign, never re-dispatch.
            result_entry = self._client.get_entry(operation_id=operation_id, phase="RESULT")
            if result_entry is not None:
                recovered = recover_result_from_entry(
                    entry=result_entry, operation_id=operation_id,
                    binding_digest=binding_digest, executor_public_key=self._pubkey,
                )
                head = self._client.get_head()
                state = "SUCCEEDED" if recovered["result"].get("status") != "FAILED" else "FAILED"
                self._store.restore_completed(
                    con, operation_id=operation_id, binding_digest=binding_digest,
                    binding=binding.as_dict(), state=state, result=recovered["result"],
                    receipt=recovered["receipt"], now=self._now(),
                )
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
                return dict(recovered["receipt"])

            # (4) Append INTENT BEFORE dispatch.
            try:
                intent_res = self._client.append_intent(
                    operation_id=operation_id, binding_digest=binding_digest
                )
            except JournalClientError as exc:
                raise E1CFailClosed(f"INTENT_{exc.code}", exc.message) from exc
            intent_seq = int(intent_res["entry"]["seq"])

            # (5) Execute via the frozen four-gate chain.  Gate logic is UNCHANGED.
            #     The store_con reuses the A1 connection; before_store_commit
            #     appends Journal RESULT AFTER receipt signing, BEFORE local
            #     insert/commit -- the authoritative ordering fix (C1).
            receipt = self._executor.execute_e1(
                pending_execution=pending_execution,
                store_con=con,
                before_store_commit=lambda r: self._append_result_hook(
                    operation_id=operation_id, binding_digest=binding_digest, receipt=r
                ),
                **dict(dispatch_args),
            )
            if not isinstance(receipt, Mapping) or "payload" not in receipt:
                raise E1CFailClosed("BAD_RECEIPT", "execute_e1 returned no original Receipt")
            receipt_dict = dict(receipt)
            result_value = receipt_dict["payload"].get("result")

            # (6) Advance the local sync cursor AFTER authoritative RESULT.
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

    @staticmethod
    def _now() -> int:
        import time
        return int(time.time())
