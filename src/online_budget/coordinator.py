from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json_bytes, is_sha256, public_key_digest, public_key_bytes, b64encode
from .errors import (
    ConfigurationMismatch, CoordinatorIndeterminate, GatewayNotAuthorized,
    GlobalBudgetExceeded, GrantRejected, LeaseCapExceeded, LeaseInactive,
    LeaseNotRegistered, OperationBindingConflict,
)
from .grants import (
    LeaseRevocation, OnlineLeaseGrant, execution_grant_digest,
    validate_execution_grant_v2, verify_online_lease_grant, verify_revocation,
)
from .receipts import BudgetReceipt, sign_budget_receipt


class OnlineBudgetCoordinator:
    """Single-node Online v1 Coordinator. SQLite is opened only by this service."""

    def __init__(
        self,
        *,
        coordinator_id: str,
        global_budget_id: str,
        global_quota_limit: int,
        issuer_public_key: Ed25519PublicKey,
        coordinator_private_key: Ed25519PrivateKey,
        coordinator_key_id: str,
        database_path: str | Path,
        gateways: Mapping[str, Ed25519PublicKey],
        clock=None,
    ) -> None:
        for name, value in (("coordinator_id", coordinator_id), ("global_budget_id", global_budget_id), ("coordinator_key_id", coordinator_key_id)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")
        if not isinstance(global_quota_limit, int) or isinstance(global_quota_limit, bool) or global_quota_limit <= 0:
            raise ValueError("global_quota_limit must be a positive integer")
        if not isinstance(issuer_public_key, Ed25519PublicKey) or not isinstance(coordinator_private_key, Ed25519PrivateKey):
            raise ValueError("Issuer and Coordinator keys must be Ed25519 keys")
        if not gateways:
            raise ValueError("at least one Gateway key must be enrolled")
        self.coordinator_id = coordinator_id
        self.global_budget_id = global_budget_id
        self.global_quota_limit = global_quota_limit
        self.issuer_public_key = issuer_public_key
        self.coordinator_private_key = coordinator_private_key
        self.coordinator_key_id = coordinator_key_id
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock or (lambda: int(time.time()))
        self.issuer_digest = public_key_digest(issuer_public_key)
        self.coordinator_public_key = coordinator_private_key.public_key()
        self.coordinator_public_key_digest = public_key_digest(self.coordinator_public_key)
        self._init_schema()
        self._initialize_meta()
        for gateway_id, public_key in gateways.items():
            self.enroll_gateway(gateway_id, public_key)
        # D9.3.1: never serve from a database that fails physical or ledger checks.
        self._startup_integrity_check()

    def _startup_integrity_check(self) -> None:
        """Fail startup closed on SQLite or Online budget-ledger inconsistency."""
        try:
            with self._db() as con:
                integrity_rows = con.execute("PRAGMA integrity_check").fetchall()
                integrity = [str(row[0]) for row in integrity_rows]
                if integrity != ["ok"]:
                    raise CoordinatorIndeterminate("SQLite integrity_check failed: " + "; ".join(integrity))
                foreign_key_errors = con.execute("PRAGMA foreign_key_check").fetchall()
                if foreign_key_errors:
                    raise CoordinatorIndeterminate("SQLite foreign_key_check reported violations")
            self.assert_invariants()
        except CoordinatorIndeterminate:
            raise
        except sqlite3.DatabaseError as exc:
            raise CoordinatorIndeterminate("Coordinator database integrity validation failed") from exc

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.database_path, timeout=30.0, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA busy_timeout=30000")
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA synchronous=FULL")
        return con

    @contextmanager
    def _db(self):
        con = self._connect()
        try:
            yield con
        finally:
            con.close()

    def _init_schema(self) -> None:
        with self._db() as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript("""
                CREATE TABLE IF NOT EXISTS budget_meta (
                    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
                    coordinator_id TEXT NOT NULL,
                    global_budget_id TEXT NOT NULL,
                    global_quota_limit INTEGER NOT NULL CHECK(global_quota_limit > 0),
                    global_used_count INTEGER NOT NULL CHECK(global_used_count >= 0),
                    next_global_sequence INTEGER NOT NULL CHECK(next_global_sequence >= 1),
                    issuer_public_key_digest TEXT NOT NULL,
                    coordinator_key_id TEXT NOT NULL,
                    coordinator_public_key_digest TEXT NOT NULL,
                    health TEXT NOT NULL CHECK(health IN ('READY','INDETERMINATE')),
                    health_reason TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS gateways (
                    gateway_id TEXT PRIMARY KEY,
                    public_key_b64 TEXT NOT NULL,
                    key_digest TEXT NOT NULL,
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1))
                );
                CREATE TABLE IF NOT EXISTS leases (
                    lease_id TEXT PRIMARY KEY,
                    issuer_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL UNIQUE,
                    nonce TEXT NOT NULL UNIQUE,
                    grant_digest TEXT NOT NULL UNIQUE,
                    grant_json TEXT NOT NULL,
                    quota_limit INTEGER NOT NULL CHECK(quota_limit > 0),
                    used_count INTEGER NOT NULL DEFAULT 0 CHECK(used_count >= 0),
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    coordinator_audience TEXT NOT NULL,
                    allowed_gateway_ids_json TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    context_digest TEXT NOT NULL,
                    allowed_tools_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('ACTIVE','EXPIRED','REVOKED'))
                );
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    gateway_id TEXT NOT NULL,
                    lease_id TEXT NOT NULL,
                    global_lease_grant_digest TEXT NOT NULL,
                    execution_grant_digest TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    global_sequence INTEGER NOT NULL UNIQUE,
                    lease_used_count INTEGER NOT NULL,
                    global_used_count INTEGER NOT NULL,
                    committed_at INTEGER NOT NULL,
                    FOREIGN KEY(lease_id) REFERENCES leases(lease_id)
                );
                CREATE TABLE IF NOT EXISTS receipts (
                    operation_id TEXT PRIMARY KEY,
                    receipt_json TEXT NOT NULL,
                    signature_b64 TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES operations(operation_id)
                );
                CREATE TABLE IF NOT EXISTS revocations (
                    revocation_id TEXT PRIMARY KEY,
                    lease_id TEXT NOT NULL,
                    revocation_digest TEXT NOT NULL,
                    revoked_at INTEGER NOT NULL,
                    FOREIGN KEY(lease_id) REFERENCES leases(lease_id)
                );
                CREATE INDEX IF NOT EXISTS ix_operations_lease ON operations(lease_id);
                CREATE INDEX IF NOT EXISTS ix_leases_state ON leases(state);
            """)

    def _initialize_meta(self) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                row = con.execute("SELECT * FROM budget_meta WHERE singleton_id=1").fetchone()
                config = (
                    self.coordinator_id, self.global_budget_id, self.global_quota_limit,
                    self.issuer_digest, self.coordinator_key_id, self.coordinator_public_key_digest,
                )
                if row is None:
                    con.execute(
                        "INSERT INTO budget_meta(singleton_id,coordinator_id,global_budget_id,global_quota_limit,"
                        "global_used_count,next_global_sequence,issuer_public_key_digest,coordinator_key_id,"
                        "coordinator_public_key_digest,health,health_reason) VALUES(1,?,?,?,0,1,?,?,?,'READY','')",
                        config,
                    )
                else:
                    stored = (
                        row["coordinator_id"], row["global_budget_id"], row["global_quota_limit"],
                        row["issuer_public_key_digest"], row["coordinator_key_id"], row["coordinator_public_key_digest"],
                    )
                    if stored != config:
                        raise ConfigurationMismatch("Coordinator epoch, quota, Issuer key or signing identity changed")
                con.commit()
            except Exception:
                con.rollback()
                raise

    def enroll_gateway(self, gateway_id: str, public_key: Ed25519PublicKey) -> None:
        if not isinstance(gateway_id, str) or not gateway_id.strip() or not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("valid gateway_id and Ed25519 public key are required")
        raw = public_key_bytes(public_key)
        key_digest = public_key_digest(public_key)
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT key_digest FROM gateways WHERE gateway_id=?", (gateway_id,)).fetchone()
            if row is not None and row["key_digest"] != key_digest:
                con.rollback()
                raise ConfigurationMismatch("Gateway key rotation requires an explicit enrollment procedure")
            # D9.3.1: startup enrollment inserts new identities but never re-enables an existing disabled one.
            if row is None:
                con.execute(
                    "INSERT INTO gateways(gateway_id,public_key_b64,key_digest,enabled) VALUES(?,?,?,1)",
                    (gateway_id, b64encode(raw), key_digest),
                )
            con.commit()

    def gateway_public_key(self, gateway_id: str) -> Ed25519PublicKey | None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from .canonical import public_key_from_b64
        with self._db() as con:
            row = con.execute("SELECT public_key_b64,enabled FROM gateways WHERE gateway_id=?", (gateway_id,)).fetchone()
        if row is None or row["enabled"] != 1:
            return None
        return public_key_from_b64(row["public_key_b64"])

    def disable_gateway(self, gateway_id: str) -> None:
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("UPDATE gateways SET enabled=0 WHERE gateway_id=?", (gateway_id,))
            con.commit()

    def _assert_ready(self, con: sqlite3.Connection) -> sqlite3.Row:
        row = con.execute("SELECT * FROM budget_meta WHERE singleton_id=1").fetchone()
        if row is None:
            raise CoordinatorIndeterminate("Coordinator budget metadata is missing")
        if row["health"] != "READY":
            raise CoordinatorIndeterminate(row["health_reason"] or "Coordinator is not READY")
        return row

    @staticmethod
    def _require_gateway_enabled(con: sqlite3.Connection, gateway_id: str) -> None:
        row = con.execute("SELECT enabled FROM gateways WHERE gateway_id=?", (gateway_id,)).fetchone()
        if row is None or int(row["enabled"]) != 1:
            raise GatewayNotAuthorized("Gateway is not enrolled or has been disabled")

    def _assert_gateway_allowed(
        self, con: sqlite3.Connection, gateway_id: str, grant: OnlineLeaseGrant,
    ) -> None:
        if gateway_id not in grant.allowed_gateway_ids:
            raise GatewayNotAuthorized("Gateway ID is not listed in the signed Online Lease Grant")
        self._require_gateway_enabled(con, gateway_id)

    def register_lease(self, gateway_id: str, grant: OnlineLeaseGrant) -> dict[str, Any]:
        try:
            verify_online_lease_grant(grant, self.issuer_public_key)
        except ValueError as exc:
            raise GrantRejected(str(exc)) from exc
        if grant.global_budget_id != self.global_budget_id or grant.coordinator_audience != self.coordinator_id:
            raise GrantRejected("Online Lease Grant belongs to another epoch or Coordinator")
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                self._assert_ready(con)
                self._assert_gateway_allowed(con, gateway_id, grant)
                row = con.execute("SELECT * FROM leases WHERE lease_id=?", (grant.lease_id,)).fetchone()
                if row is not None:
                    if row["grant_digest"] != grant.grant_digest:
                        raise GrantRejected("lease_id is already bound to different signed content")
                    con.commit()
                    return self._lease_row(row)
                now = int(self.clock())
                if now < grant.issued_at or now >= grant.expires_at:
                    raise GrantRejected("Online Lease Grant is not currently valid for registration")
                con.execute(
                    "INSERT INTO leases(lease_id,issuer_id,grant_id,nonce,grant_digest,grant_json,quota_limit,used_count,"
                    "issued_at,expires_at,coordinator_audience,allowed_gateway_ids_json,subject_id,context_digest,"
                    "allowed_tools_json,state) VALUES(?,?,?,?,?,?,?,0,?,?,?,?,?,?,?,'ACTIVE')",
                    (grant.lease_id, grant.issuer_id, grant.grant_id, grant.nonce, grant.grant_digest,
                     canonical_json_bytes(grant.as_dict()).decode("utf-8"), grant.quota_limit,
                     grant.issued_at, grant.expires_at, grant.coordinator_audience,
                     canonical_json_bytes(sorted(grant.allowed_gateway_ids)).decode("utf-8"), grant.subject_id,
                     grant.context_digest,
                     canonical_json_bytes([p.as_dict() for p in sorted(grant.allowed_tools, key=lambda x:x.tool_name)]).decode("utf-8")),
                )
                con.commit()
                return self.get_lease(grant.lease_id)
            except sqlite3.IntegrityError as exc:
                con.rollback()
                raise GrantRejected("grant_id, nonce or grant digest is already registered") from exc
            except Exception:
                con.rollback()
                raise

    @staticmethod
    def _lease_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "lease_id": row["lease_id"], "grant_id": row["grant_id"],
            "grant_digest": row["grant_digest"], "quota_limit": int(row["quota_limit"]),
            "used_count": int(row["used_count"]), "issued_at": int(row["issued_at"]),
            "expires_at": int(row["expires_at"]), "state": row["state"],
            "allowed_gateway_ids": json.loads(row["allowed_gateway_ids_json"]),
        }

    def get_lease(self, lease_id: str) -> dict[str, Any] | None:
        with self._db() as con:
            row = con.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
        return None if row is None else self._lease_row(row)

    def get_lease_for_gateway(self, gateway_id: str, lease_id: str) -> dict[str, Any] | None:
        """Read Lease metadata only while the caller remains an enabled Gateway."""
        with self._db() as con:
            con.execute("BEGIN")
            self._require_gateway_enabled(con, gateway_id)
            row = con.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
            if row is None:
                con.commit()
                return None
            allowed = json.loads(row["allowed_gateway_ids_json"])
            if gateway_id not in allowed:
                raise GatewayNotAuthorized("Gateway is not authorized to inspect this Lease")
            result = self._lease_row(row)
            con.commit()
            return result

    def revoke_lease(self, gateway_id: str, record: LeaseRevocation) -> dict[str, Any]:
        try:
            verify_revocation(record, self.issuer_public_key)
        except ValueError as exc:
            raise GrantRejected(str(exc)) from exc
        if record.global_budget_id != self.global_budget_id:
            raise GrantRejected("revocation targets another budget epoch")
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                self._assert_ready(con)
                self._require_gateway_enabled(con, gateway_id)
                old = con.execute("SELECT * FROM revocations WHERE revocation_id=?", (record.revocation_id,)).fetchone()
                if old is not None:
                    if old["revocation_digest"] != record.revocation_digest:
                        raise GrantRejected("revocation_id is already bound to different content")
                    lease = con.execute("SELECT * FROM leases WHERE lease_id=?", (record.lease_id,)).fetchone()
                    con.commit()
                    return self._lease_row(lease)
                lease = con.execute("SELECT * FROM leases WHERE lease_id=?", (record.lease_id,)).fetchone()
                if lease is None:
                    raise LeaseNotRegistered("cannot revoke an unregistered Lease")
                if lease["grant_digest"] != record.grant_digest or lease["issuer_id"] != record.issuer_id:
                    raise GrantRejected("revocation does not match the registered Lease")
                now = int(self.clock())
                if record.revoked_at < int(lease["issued_at"]) or record.revoked_at > now:
                    raise GrantRejected("revoked_at is outside the accepted time interval")
                con.execute("INSERT INTO revocations(revocation_id,lease_id,revocation_digest,revoked_at) VALUES(?,?,?,?)",
                            (record.revocation_id, record.lease_id, record.revocation_digest, record.revoked_at))
                con.execute("UPDATE leases SET state='REVOKED' WHERE lease_id=?", (record.lease_id,))
                con.commit()
                return self.get_lease(record.lease_id)
            except Exception:
                con.rollback()
                raise

    @staticmethod
    def _pair_grants(gateway_id: str, online: OnlineLeaseGrant, execution: Mapping[str, Any], coordinator_id: str) -> str:
        if online.coordinator_audience != coordinator_id or gateway_id not in online.allowed_gateway_ids:
            raise GatewayNotAuthorized("Gateway or Coordinator is outside the signed Lease scope")
        shared = {
            "issuer_id": online.issuer_id, "grant_id": online.grant_id,
            "lease_id": online.lease_id, "nonce": online.nonce,
            "quota_limit": online.quota_limit, "issued_at": online.issued_at,
            "expires_at": online.expires_at, "subject_id": online.subject_id,
            "context_digest": online.context_digest,
            "allowed_tools": [p.as_dict() for p in sorted(online.allowed_tools, key=lambda x:x.tool_name)],
        }
        for name, expected in shared.items():
            actual = execution.get(name)
            if name == "allowed_tools" and isinstance(actual, list):
                actual = sorted(actual, key=lambda x:x.get("tool_name", ""))
            if actual != expected:
                raise GrantRejected(f"paired Execution Grant does not match Online Lease Grant field: {name}")
        if execution["audience"] != gateway_id:
            raise GatewayNotAuthorized("Execution Grant audience does not match authenticated Gateway")
        return execution_grant_digest(execution)

    def consume(
        self,
        gateway_id: str,
        online_grant: OnlineLeaseGrant,
        execution_grant: Mapping[str, Any],
        *, operation_id: str,
        request_digest: str,
    ) -> BudgetReceipt:
        try:
            verify_online_lease_grant(online_grant, self.issuer_public_key)
            execution = validate_execution_grant_v2(execution_grant, self.issuer_public_key)
        except ValueError as exc:
            raise GrantRejected(str(exc)) from exc
        if online_grant.global_budget_id != self.global_budget_id:
            raise GrantRejected("Online Lease Grant belongs to another budget epoch")
        if not isinstance(operation_id, str) or not operation_id.strip() or execution["operation_id"] != operation_id:
            raise GrantRejected("operation_id must match the signed Execution Grant")
        if not is_sha256(request_digest):
            raise GrantRejected("request_digest must be a sha256 digest")
        exec_digest = self._pair_grants(gateway_id, online_grant, execution, self.coordinator_id)
        grant_digest = online_grant.grant_digest
        with self._db() as con:
            con.execute("BEGIN IMMEDIATE")
            try:
                meta = self._assert_ready(con)
                self._assert_gateway_allowed(con, gateway_id, online_grant)
                existing = con.execute("SELECT * FROM operations WHERE operation_id=?", (operation_id,)).fetchone()
                binding = (gateway_id, online_grant.lease_id, grant_digest, exec_digest, request_digest)
                if existing is not None:
                    actual = (existing["gateway_id"], existing["lease_id"], existing["global_lease_grant_digest"],
                              existing["execution_grant_digest"], existing["request_digest"])
                    if actual != binding:
                        raise OperationBindingConflict("operation_id is already bound to a different Gateway, Lease or request")
                    rec = con.execute("SELECT receipt_json,signature_b64 FROM receipts WHERE operation_id=?", (operation_id,)).fetchone()
                    if rec is None:
                        con.execute("UPDATE budget_meta SET health='INDETERMINATE',health_reason=? WHERE singleton_id=1",
                                    ("committed operation is missing its receipt",))
                        con.commit()
                        raise CoordinatorIndeterminate("committed operation is missing its receipt")
                    payload = json.loads(rec["receipt_json"])
                    signature = rec["signature_b64"]
                    con.commit()
                    return BudgetReceipt(payload, signature)

                lease = con.execute("SELECT * FROM leases WHERE lease_id=?", (online_grant.lease_id,)).fetchone()
                if lease is None:
                    raise LeaseNotRegistered("Lease must be registered before consumption")
                if lease["grant_digest"] != grant_digest:
                    raise GrantRejected("Online Lease Grant differs from registered signed content")
                now = int(self.clock())
                if now < int(lease["issued_at"]):
                    raise GrantRejected("Lease is not yet valid")
                if now >= int(lease["expires_at"]):
                    con.execute("UPDATE leases SET state='EXPIRED' WHERE lease_id=? AND state='ACTIVE'", (lease["lease_id"],))
                    con.commit()
                    raise LeaseInactive("Lease has expired")
                if now < int(execution["issued_at"]) or now >= int(execution["expires_at"]):
                    raise GrantRejected("Execution Grant is not currently valid")
                if lease["state"] == "REVOKED":
                    raise LeaseInactive("Lease has been revoked")
                if lease["state"] == "EXPIRED":
                    raise LeaseInactive("Lease has expired")
                if gateway_id not in json.loads(lease["allowed_gateway_ids_json"]):
                    raise GatewayNotAuthorized("Gateway is not allowed by registered Lease")
                if int(lease["used_count"]) >= int(lease["quota_limit"]):
                    raise LeaseCapExceeded("Lease quota cap is exhausted")
                global_used = int(meta["global_used_count"])
                if global_used >= int(meta["global_quota_limit"]):
                    raise GlobalBudgetExceeded("global budget is exhausted")
                sequence = int(meta["next_global_sequence"])
                next_lease_used = int(lease["used_count"]) + 1
                next_global_used = global_used + 1
                committed_at = now
                receipt_payload = {
                    "receipt_version": 1,
                    "coordinator_id": self.coordinator_id,
                    "coordinator_key_id": self.coordinator_key_id,
                    "global_budget_id": self.global_budget_id,
                    "global_sequence": sequence,
                    "gateway_id": gateway_id,
                    "lease_id": online_grant.lease_id,
                    "global_lease_grant_digest": grant_digest,
                    "execution_grant_digest": exec_digest,
                    "operation_id": operation_id,
                    "request_digest": request_digest,
                    "lease_used_count": next_lease_used,
                    "global_used_count": next_global_used,
                    "committed_at": committed_at,
                }
                receipt = sign_budget_receipt(receipt_payload, self.coordinator_private_key)
                changed = con.execute("UPDATE leases SET used_count=? WHERE lease_id=? AND used_count=?",
                                      (next_lease_used, online_grant.lease_id, int(lease["used_count"]))).rowcount
                if changed != 1:
                    raise CoordinatorIndeterminate("Lease usage changed unexpectedly during serialized consume")
                con.execute("UPDATE budget_meta SET global_used_count=?,next_global_sequence=? WHERE singleton_id=1",
                            (next_global_used, sequence + 1))
                con.execute(
                    "INSERT INTO operations(operation_id,gateway_id,lease_id,global_lease_grant_digest,"
                    "execution_grant_digest,request_digest,global_sequence,lease_used_count,global_used_count,committed_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (operation_id, gateway_id, online_grant.lease_id, grant_digest, exec_digest, request_digest,
                     sequence, next_lease_used, next_global_used, committed_at),
                )
                rec_json = canonical_json_bytes(receipt_payload).decode("utf-8")
                rec_digest = receipt.receipt_digest
                con.execute("INSERT INTO receipts(operation_id,receipt_json,signature_b64,receipt_digest) VALUES(?,?,?,?)",
                            (operation_id, rec_json, receipt.signature_b64, rec_digest))
                con.commit()
                return receipt
            except Exception:
                if con.in_transaction:
                    con.rollback()
                raise

    def lookup_operation(self, gateway_id: str, operation_id: str) -> BudgetReceipt | None:
        with self._db() as con:
            con.execute("BEGIN")
            self._require_gateway_enabled(con, gateway_id)
            row = con.execute(
                "SELECT o.gateway_id,r.receipt_json,r.signature_b64 FROM operations o "
                "LEFT JOIN receipts r ON r.operation_id=o.operation_id WHERE o.operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                con.commit()
                return None
            if row["gateway_id"] != gateway_id:
                raise OperationBindingConflict("operation_id belongs to another Gateway")
            if row["receipt_json"] is None:
                raise CoordinatorIndeterminate("operation receipt is missing")
            receipt = BudgetReceipt(json.loads(row["receipt_json"]), row["signature_b64"])
            con.commit()
            return receipt

    def assert_invariants(self) -> dict[str, int]:
        with self._db() as con:
            meta = self._assert_ready(con)
            leases = con.execute("SELECT COALESCE(SUM(used_count),0) AS used, COUNT(*) AS n FROM leases").fetchone()
            operations = con.execute("SELECT COUNT(*) AS n, MIN(global_sequence) AS lo, MAX(global_sequence) AS hi FROM operations").fetchone()
            receipts = con.execute("SELECT COUNT(*) AS n FROM receipts").fetchone()
            bad = con.execute(
                "SELECT COUNT(*) AS n FROM operations o LEFT JOIN receipts r ON r.operation_id=o.operation_id "
                "WHERE r.operation_id IS NULL OR r.receipt_digest IS NULL"
            ).fetchone()["n"]
            invalid_lease = con.execute("SELECT COUNT(*) AS n FROM leases WHERE used_count<0 OR used_count>quota_limit").fetchone()["n"]
            mismatched_lease_counts = con.execute(
                "SELECT COUNT(*) AS n FROM leases l LEFT JOIN operations o ON o.lease_id=l.lease_id "
                "GROUP BY l.lease_id HAVING l.used_count<>COUNT(o.operation_id)"
            ).fetchall()
            operation_rows = con.execute(
                "SELECT o.*,r.receipt_json,r.signature_b64,r.receipt_digest FROM operations o "
                "JOIN receipts r ON r.operation_id=o.operation_id ORDER BY o.global_sequence"
            ).fetchall()
            receipt_mismatch = False
            from .receipts import BudgetReceipt, verify_budget_receipt
            for op in operation_rows:
                try:
                    receipt = BudgetReceipt(json.loads(op["receipt_json"]), op["signature_b64"])
                    expected = {
                        "coordinator_id": self.coordinator_id,
                        "global_budget_id": self.global_budget_id,
                        "global_sequence": int(op["global_sequence"]),
                        "gateway_id": op["gateway_id"],
                        "lease_id": op["lease_id"],
                        "global_lease_grant_digest": op["global_lease_grant_digest"],
                        "execution_grant_digest": op["execution_grant_digest"],
                        "operation_id": op["operation_id"],
                        "request_digest": op["request_digest"],
                        "lease_used_count": int(op["lease_used_count"]),
                        "global_used_count": int(op["global_used_count"]),
                        "committed_at": int(op["committed_at"]),
                    }
                    if (not verify_budget_receipt(receipt, self.coordinator_public_key, expected=expected)
                            or receipt.receipt_digest != op["receipt_digest"]):
                        receipt_mismatch = True
                        break
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    receipt_mismatch = True
                    break
            used = int(meta["global_used_count"])
            if (int(leases["used"]) != used or int(operations["n"]) != used or int(receipts["n"]) != used
                    or int(meta["next_global_sequence"]) != used + 1
                    or bad or invalid_lease or mismatched_lease_counts or receipt_mismatch
                    or used > int(meta["global_quota_limit"])
                    or (used == 0 and operations["lo"] is not None)
                    or (used > 0 and (int(operations["lo"]) != 1 or int(operations["hi"]) != used))):
                with self._db() as write:
                    write.execute("BEGIN IMMEDIATE")
                    write.execute("UPDATE budget_meta SET health='INDETERMINATE',health_reason=? WHERE singleton_id=1",
                                  ("online budget accounting invariant violation",))
                    write.commit()
                raise CoordinatorIndeterminate("online budget accounting invariant violation")
            return {"global_used_count": used, "global_quota_limit": int(meta["global_quota_limit"]),
                    "lease_used_total": int(leases["used"]), "operation_count": int(operations["n"]),
                    "receipt_count": int(receipts["n"])}

    def inspect(self) -> dict[str, Any]:
        with self._db() as con:
            meta = con.execute("SELECT * FROM budget_meta WHERE singleton_id=1").fetchone()
            leases = [self._lease_row(x) for x in con.execute("SELECT * FROM leases ORDER BY lease_id")]
            return {
                "coordinator_id": self.coordinator_id,
                "global_budget_id": self.global_budget_id,
                "global_quota_limit": int(meta["global_quota_limit"]),
                "global_used_count": int(meta["global_used_count"]),
                "next_global_sequence": int(meta["next_global_sequence"]),
                "health": meta["health"], "health_reason": meta["health_reason"],
                "leases": leases,
            }
