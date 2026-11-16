from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import public_key_digest
from .client import OnlineBudgetClient
from .errors import GrantRejected, OperationBindingConflict
from .grants import OnlineLeaseGrant, execution_grant_dict, execution_grant_digest, verify_online_lease_grant, validate_execution_grant_v2
from .receipts import BudgetReceipt, verify_budget_receipt
from .receipt_chain import build_online_receipt_chain


@dataclass(frozen=True)
class OnlineBudgetExecutionReceipt:
    lease_id: str
    operation_id: str
    request_digest: str
    counter_value: int
    global_budget_id: str
    global_sequence: int
    lease_used_count: int
    global_lease_grant_digest: str
    coordinator_receipt_digest: str
    coordinator_receipt: dict[str, Any]


@dataclass(frozen=True)
class _IdentityPath:
    path: str


@dataclass(frozen=True)
class _RemoteCounterIdentity:
    path: str
    lock_path: str


class OnlineBudgetExecutionAdapter:
    """E4.8.3-compatible Online adapter; all durable state remains server-side.

    The path-like identity fields are opaque endpoint identity labels needed by the
    frozen E4.8.3 Gateway's Broker identity hasher. They are not local storage paths.
    """

    is_global_budget_adapter = True

    def __init__(
        self, *, client: OnlineBudgetClient, issuer_public_key: Ed25519PublicKey,
        global_budget_id: str, global_quota_limit: int, coordinator_id: str,
        receipt_cache_path: str | Path,
    ) -> None:
        if client.coordinator_id != coordinator_id:
            raise ValueError("client and adapter Coordinator identities differ")
        # D9.3.1: a Client pinned to another budget epoch cannot back this Adapter.
        if client.global_budget_id != global_budget_id:
            raise ValueError("client and adapter budget epoch identities differ")
        self.client = client
        self.issuer_public_key = issuer_public_key
        self.global_budget_id = global_budget_id
        self.global_quota_limit = global_quota_limit
        self.coordinator_id = coordinator_id
        self.receipt_cache_path = Path(receipt_cache_path)
        self.receipt_cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.issuer_public_key_digest = public_key_digest(issuer_public_key)
        identity = hashlib.sha256(
            f"{client.base_url}|{coordinator_id}|{global_budget_id}|{global_quota_limit}|{self.issuer_public_key_digest}|{self.receipt_cache_path.resolve()}".encode()
        ).hexdigest()
        self.config_digest = "sha256:" + identity
        self.journal = _IdentityPath(f"online-coordinator-{identity}-journal")
        self.counter = _RemoteCounterIdentity(
            path=f"online-coordinator-{identity}-counter",
            lock_path=f"online-coordinator-{identity}-counter-lock",
        )
        self.lock_path = Path(f"online-coordinator-{identity}-broker-lock")
        self._bindings: dict[str, tuple[dict[str, Any], OnlineLeaseGrant]] = {}
        self._init_receipt_cache()

    def _cache_connect(self):
        con = sqlite3.connect(self.receipt_cache_path, timeout=30.0, isolation_level=None)
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("PRAGMA synchronous=FULL")
        return con

    @contextmanager
    def _cache_db(self):
        """Open a cache connection and always close its file handle.

        sqlite3.Connection's context manager commits/rolls back transactions but
        does not close the connection. Explicit close is required on Windows so
        a completed request does not keep the WAL database locked during
        directory cleanup or cache replacement.
        """
        con = self._cache_connect()
        try:
            yield con
        finally:
            try:
                if con.in_transaction:
                    con.rollback()
            finally:
                con.close()

    def _init_receipt_cache(self) -> None:
        with self._cache_db() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute(
                "CREATE TABLE IF NOT EXISTS coordinator_receipts ("
                "operation_id TEXT PRIMARY KEY, gateway_id TEXT NOT NULL, lease_id TEXT NOT NULL, "
                "global_lease_grant_digest TEXT NOT NULL, execution_grant_digest TEXT NOT NULL, "
                "request_digest TEXT NOT NULL, receipt_json TEXT NOT NULL, signature_b64 TEXT NOT NULL, "
                "receipt_digest TEXT NOT NULL)"
            )
            con.execute(
                "CREATE TABLE IF NOT EXISTS grant_bindings ("
                "execution_grant_digest TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE, "
                "execution_grant_json TEXT NOT NULL, online_lease_grant_json TEXT NOT NULL)"
            )

    def _persist_binding(self, execution: dict[str, Any], online_grant: OnlineLeaseGrant) -> None:
        execution_digest = execution_grant_digest(execution)
        execution_json = json.dumps(execution, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        online_json = json.dumps(online_grant.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._cache_db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                old = con.execute(
                    "SELECT operation_id,execution_grant_json,online_lease_grant_json FROM grant_bindings WHERE execution_grant_digest=?",
                    (execution_digest,),
                ).fetchone()
                if old is not None and old != (execution["operation_id"], execution_json, online_json):
                    raise OperationBindingConflict("execution Grant digest is already bound to different local metadata")
                con.execute(
                    "INSERT OR IGNORE INTO grant_bindings(execution_grant_digest,operation_id,execution_grant_json,online_lease_grant_json) "
                    "VALUES(?,?,?,?)", (execution_digest, execution["operation_id"], execution_json, online_json),
                )
                con.commit()
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def _load_binding(self, execution_digest_value: str) -> tuple[dict[str, Any], OnlineLeaseGrant] | None:
        with self._cache_db() as con:
            row = con.execute(
                "SELECT execution_grant_json,online_lease_grant_json FROM grant_bindings WHERE execution_grant_digest=?",
                (execution_digest_value,),
            ).fetchone()
        if row is None:
            return None
        execution = json.loads(row[0])
        online = OnlineLeaseGrant.from_dict(json.loads(row[1]))
        # Local metadata is not trusted merely because it is in SQLite: re-verify both signed objects.
        verify_online_lease_grant(online, self.issuer_public_key)
        execution = validate_execution_grant_v2(execution, self.issuer_public_key)
        online_shared = {
            "issuer_id": online.issuer_id, "grant_id": online.grant_id,
            "lease_id": online.lease_id, "nonce": online.nonce,
            "quota_limit": online.quota_limit, "issued_at": online.issued_at,
            "expires_at": online.expires_at, "subject_id": online.subject_id,
            "context_digest": online.context_digest,
            "allowed_tools": tuple(sorted((x.tool_name, x.schema_hash) for x in online.allowed_tools)),
        }
        if (execution_grant_digest(execution) != execution_digest_value
                or self._shared_execution_fields(execution) != online_shared
                or execution["audience"] != self.client.gateway_id
                or self.client.gateway_id not in online.allowed_gateway_ids
                or online.global_budget_id != self.global_budget_id
                or online.coordinator_audience != self.coordinator_id):
            raise GrantRejected("persisted Execution/Online Lease Grant pair is invalid")
        return execution, online

    def _cached_receipt(self, operation_id: str) -> tuple[BudgetReceipt, dict[str, Any]] | None:
        with self._cache_db() as con:
            row = con.execute(
                "SELECT gateway_id,lease_id,global_lease_grant_digest,execution_grant_digest,request_digest,"
                "receipt_json,signature_b64,receipt_digest FROM coordinator_receipts WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        if row is None:
            return None
        receipt = BudgetReceipt(json.loads(row[5]), row[6])
        if receipt.receipt_digest != row[7]:
            raise GrantRejected("locally cached Coordinator receipt digest is corrupt")
        expected = {
            "coordinator_id": self.coordinator_id,
            "global_budget_id": self.global_budget_id,
            "gateway_id": row[0], "lease_id": row[1],
            "global_lease_grant_digest": row[2], "execution_grant_digest": row[3],
            "operation_id": operation_id, "request_digest": row[4],
        }
        if not verify_budget_receipt(receipt, self.client.coordinator_public_key, expected=expected):
            raise GrantRejected("locally cached Coordinator receipt failed signature or binding verification")
        metadata = {"gateway_id": row[0], "lease_id": row[1], "global_lease_grant_digest": row[2],
                    "execution_grant_digest": row[3], "request_digest": row[4]}
        return receipt, metadata

    def _persist_receipt(self, receipt: BudgetReceipt) -> None:
        p = receipt.payload
        receipt_json = json.dumps(p, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._cache_db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT receipt_digest,execution_grant_digest,request_digest FROM coordinator_receipts WHERE operation_id=?",
                                  (p["operation_id"],)).fetchone()
                if row is not None:
                    if row != (receipt.receipt_digest, p["execution_grant_digest"], p["request_digest"]):
                        raise OperationBindingConflict("local receipt cache has a conflicting operation binding")
                else:
                    con.execute(
                        "INSERT INTO coordinator_receipts(operation_id,gateway_id,lease_id,global_lease_grant_digest,"
                        "execution_grant_digest,request_digest,receipt_json,signature_b64,receipt_digest) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (p["operation_id"], p["gateway_id"], p["lease_id"], p["global_lease_grant_digest"],
                         p["execution_grant_digest"], p["request_digest"], receipt_json,
                         receipt.signature_b64, receipt.receipt_digest),
                    )
                con.commit()
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    @staticmethod
    def _shared_execution_fields(execution: dict[str, Any]) -> dict[str, Any]:
        return {
            "issuer_id": execution["issuer_id"], "grant_id": execution["grant_id"],
            "lease_id": execution["lease_id"], "nonce": execution["nonce"],
            "quota_limit": execution["quota_limit"], "issued_at": execution["issued_at"],
            "expires_at": execution["expires_at"], "subject_id": execution["subject_id"],
            "context_digest": execution["context_digest"],
            "allowed_tools": tuple(sorted((x["tool_name"], x["schema_hash"]) for x in execution["allowed_tools"])),
        }

    def bind_lease(self, execution_grant: Any, online_lease_grant: OnlineLeaseGrant) -> dict[str, str]:
        verify_online_lease_grant(online_lease_grant, self.issuer_public_key)
        execution = validate_execution_grant_v2(execution_grant_dict(execution_grant), self.issuer_public_key)
        online_shared = {
            "issuer_id": online_lease_grant.issuer_id, "grant_id": online_lease_grant.grant_id,
            "lease_id": online_lease_grant.lease_id, "nonce": online_lease_grant.nonce,
            "quota_limit": online_lease_grant.quota_limit, "issued_at": online_lease_grant.issued_at,
            "expires_at": online_lease_grant.expires_at, "subject_id": online_lease_grant.subject_id,
            "context_digest": online_lease_grant.context_digest,
            "allowed_tools": tuple(sorted((x.tool_name, x.schema_hash) for x in online_lease_grant.allowed_tools)),
        }
        if self._shared_execution_fields(execution) != online_shared:
            raise GrantRejected("Execution Grant and Online Lease Grant do not authorize the same Lease")
        if execution["audience"] != self.client.gateway_id:
            raise GrantRejected("Execution Grant audience differs from authenticated Gateway")
        if online_lease_grant.global_budget_id != self.global_budget_id:
            raise GrantRejected("Online Lease Grant belongs to another budget epoch")
        self.client.register_lease(online_lease_grant)
        key = execution_grant_digest(execution)
        self._persist_binding(execution, online_lease_grant)
        self._bindings[key] = (execution, online_lease_grant)
        return self.binding_for_execution_grant(execution_grant)

    def binding_for_execution_grant(self, execution_grant: Any) -> dict[str, str]:
        execution = validate_execution_grant_v2(execution_grant_dict(execution_grant), self.issuer_public_key)
        key = execution_grant_digest(execution)
        pair = self._bindings.get(key)
        if pair is None:
            pair = self._load_binding(key)
            if pair is not None:
                self._bindings[key] = pair
        if pair is None or pair[0].get("operation_id") != execution.get("operation_id"):
            raise GrantRejected("Execution Grant has no configured Online Lease binding")
        cached = self._cached_receipt(execution["operation_id"])
        if cached is not None:
            receipt, metadata = cached
            if (metadata["gateway_id"] != self.client.gateway_id
                    or metadata["lease_id"] != pair[1].lease_id
                    or metadata["global_lease_grant_digest"] != pair[1].grant_digest
                    or metadata["execution_grant_digest"] != key):
                raise OperationBindingConflict("cached Coordinator receipt is bound to another operation grant")
            return {"global_budget_id": pair[1].global_budget_id,
                    "global_lease_grant_digest": pair[1].grant_digest}
        lookup = self.client.lookup_lease(pair[1].lease_id)
        if not lookup.get("found") or lookup.get("grant_digest") != pair[1].grant_digest:
            raise GrantRejected("Online Lease is not registered with this Coordinator")
        # Intentionally do not reject REVOKED/EXPIRED here. A cached committed
        # receipt can be replayed; Coordinator itself rejects new allocations.
        return {"global_budget_id": pair[1].global_budget_id,
                "global_lease_grant_digest": pair[1].grant_digest}

    def consume_for_grant(
        self, execution_grant: Any, *, operation_id: str, request_digest: str,
    ) -> OnlineBudgetExecutionReceipt:
        self.binding_for_execution_grant(execution_grant)
        execution = validate_execution_grant_v2(execution_grant_dict(execution_grant), self.issuer_public_key)
        key = execution_grant_digest(execution)
        pair = self._bindings.get(key)
        if pair is None:
            raise GrantRejected("Online Lease binding disappeared")
        cached = self._cached_receipt(operation_id)
        if cached is not None:
            coordinator_receipt, metadata = cached
            if (metadata["gateway_id"] != self.client.gateway_id
                    or metadata["lease_id"] != pair[1].lease_id
                    or metadata["global_lease_grant_digest"] != pair[1].grant_digest
                    or metadata["execution_grant_digest"] != key
                    or metadata["request_digest"] != request_digest):
                raise OperationBindingConflict("operation_id is already cached with a different Online request binding")
        else:
            coordinator_receipt = self.client.consume(
                pair[1], execution, operation_id=operation_id, request_digest=request_digest,
            )
            self._persist_receipt(coordinator_receipt)
        p = coordinator_receipt.payload
        return OnlineBudgetExecutionReceipt(
            lease_id=p["lease_id"], operation_id=p["operation_id"], request_digest=p["request_digest"],
            counter_value=p["global_sequence"], global_budget_id=p["global_budget_id"],
            global_sequence=p["global_sequence"], lease_used_count=p["lease_used_count"],
            global_lease_grant_digest=p["global_lease_grant_digest"],
            coordinator_receipt_digest=coordinator_receipt.receipt_digest,
            coordinator_receipt=coordinator_receipt.as_dict(),
        )

    def coordinator_receipt_for_operation(self, operation_id: str) -> dict[str, Any] | None:
        """Return the locally cached, signature-verified Coordinator receipt."""
        cached = self._cached_receipt(operation_id)
        return None if cached is None else cached[0].as_dict()

    def build_receipt_chain(self, operation_id: str, gateway_execution_receipt: dict[str, Any]) -> dict[str, Any]:
        """Sign a link binding the E4.8.3 receipt to the verified Coordinator receipt."""
        cached = self._cached_receipt(operation_id)
        if cached is None:
            raise GrantRejected("no verified Coordinator receipt is cached for this operation")
        return build_online_receipt_chain(
            gateway_execution_receipt, cached[0], self.client.gateway_private_key,
            self.client.coordinator_public_key,
        )
