"""H2 persisted snapshot state: high-water version, cached snapshot, and bootstrap.

Implements design docs/H2_REVOCATION_DESIGN.md §5.4 (persisted HWM + restart
recovery), §5.5 (first-trust bootstrap and tri-state recovery), and the
"reject => cache unchanged" invariant of §5.2. No H1 file is modified.

Tri-state (design §5.5):
- S0_BOOTSTRAP : trusted persistent layer readable, ``initialized`` not set.
                 This is the ONLY state allowed to establish an initial HWM.
- S1_RESTORE   : readable, initialized=1, snapshot_state row present and
                 structurally valid, cached_digest matches cached_snapshot.
- S2_CORRUPT   : readable but initialized=1 while the snapshot_state row is
                 missing / damaged / digest mismatch; OR the layer unreadable.
                 Fail closed. NEVER auto re-bootstrap.

Atomicity (design §5.4.2 / §5.5.4): ``initialized``, HWM, cached snapshot and
digest are committed in ONE SQLite transaction. A pre-commit crash leaves the
old state intact (S0 stays S0 for bootstrap; HWM does not advance on refresh).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from online_budget.canonical import canonical_json_bytes

from h2_snapshot import (
    REASON_UNTRUSTED,
    SnapshotValidationError,
    snapshot_digest,
    snapshot_payload,
    validate_snapshot,
)

STATE_S0_BOOTSTRAP = "S0_BOOTSTRAP"
STATE_S1_RESTORE = "S1_RESTORE"
STATE_S2_CORRUPT = "S2_CORRUPT"

REASON_STATE_UNAVAILABLE = "SNAPSHOT_STATE_UNAVAILABLE"
BOOT_ONLINE = "BOOT_ONLINE"
BOOT_OFFLINE = "BOOT_OFFLINE"


class SnapshotStateError(ValueError):
    """Base error for persisted-state problems; ``reason`` is stable for tests."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class StateUnavailable(SnapshotStateError):
    """S2 or an operation attempted in the wrong state -> fail closed."""

    def __init__(self, reason: str = REASON_STATE_UNAVAILABLE) -> None:
        super().__init__(reason)


class StateAlreadyInitialized(SnapshotStateError):
    """bootstrap() called after initialization; never re-bootstrap (design §5.5)."""

    def __init__(self) -> None:
        super().__init__("SNAPSHOT_ALREADY_INITIALIZED")


@dataclass(frozen=True)
class RestoredState:
    high_water_version: int
    cached_snapshot: dict[str, Any]
    cached_digest: str
    bootstrap_mode: str
    last_refresh_local: float


class SnapshotStateStore:
    """SQLite-backed trusted local persistent layer for C2 snapshot state."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._init_db()

    # ---- low level ----

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path, timeout=10.0)
        con.execute("PRAGMA busy_timeout=5000")
        return con

    def _init_db(self) -> None:
        con = self._connect()
        try:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS snapshot_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    high_water_version INTEGER NOT NULL,
                    cached_snapshot TEXT NOT NULL,
                    cached_digest TEXT NOT NULL,
                    bootstrap_mode TEXT NOT NULL,
                    last_refresh_local REAL NOT NULL
                );
                """
            )
            con.commit()
        finally:
            con.close()

    # ---- state detection ----

    def state(self) -> str:
        """Return one of STATE_S0_BOOTSTRAP / STATE_S1_RESTORE / STATE_S2_CORRUPT.

        Any storage-level error is treated as S2 (fail closed), never as S0.
        """
        try:
            con = self._connect()
            try:
                row = con.execute(
                    "SELECT value FROM meta WHERE key='initialized'"
                ).fetchone()
                initialized = row is not None and row[0] == "1"
                if not initialized:
                    # No initialization marker -> first install (S0), but only
                    # if there is no orphan snapshot_state row.
                    orphan = con.execute(
                        "SELECT 1 FROM snapshot_state WHERE id=1"
                    ).fetchone()
                    if orphan is not None:
                        # initialized marker lost but state present: do NOT
                        # treat as a fresh install (would allow re-bootstrap).
                        return STATE_S2_CORRUPT
                    return STATE_S0_BOOTSTRAP
                # initialized=1: state must be present and self-consistent.
                srow = con.execute(
                    "SELECT high_water_version, cached_snapshot, cached_digest, "
                    "bootstrap_mode, last_refresh_local FROM snapshot_state WHERE id=1"
                ).fetchone()
                if srow is None:
                    return STATE_S2_CORRUPT
                return STATE_S1_RESTORE if self._validate_row(srow) is not None else STATE_S2_CORRUPT
            finally:
                con.close()
        except (sqlite3.Error, OSError, ValueError, TypeError):
            return STATE_S2_CORRUPT

    def _validate_row(self, srow: Any) -> RestoredState | None:
        """Validate structure + digest of a snapshot_state row (no time check)."""
        try:
            hwm, cached_text, digest_text, boot_mode, last_refresh = srow
            if isinstance(hwm, bool) or not isinstance(hwm, int) or hwm < 1:
                return None
            if not isinstance(cached_text, str) or not isinstance(digest_text, str):
                return None
            if isinstance(last_refresh, bool) or not isinstance(last_refresh, (int, float)):
                return None
            cached = json.loads(cached_text)
            if not isinstance(cached, dict):
                return None
            snapshot_payload(cached)  # structure check; raises ValueError
            if snapshot_digest(cached) != digest_text:
                return None
            return RestoredState(
                high_water_version=hwm,
                cached_snapshot=cached,
                cached_digest=digest_text,
                bootstrap_mode=str(boot_mode),
                last_refresh_local=float(last_refresh),
            )
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

    def restore(self) -> RestoredState:
        """Restore trusted state for S1. S0/S2 raise StateUnavailable."""
        st = self.state()
        if st != STATE_S1_RESTORE:
            raise StateUnavailable()
        con = self._connect()
        try:
            srow = con.execute(
                "SELECT high_water_version, cached_snapshot, cached_digest, "
                "bootstrap_mode, last_refresh_local FROM snapshot_state WHERE id=1"
            ).fetchone()
        finally:
            con.close()
        restored = self._validate_row(srow) if srow is not None else None
        if restored is None:
            raise StateUnavailable()
        return restored

    # ---- bootstrap (S0 only) ----

    def bootstrap(
        self,
        snapshot: Mapping[str, Any],
        *,
        trusted_keys: Mapping[str, Ed25519PublicKey],
        trusted_issuer: str,
        now: float,
        bootstrap_mode: str = BOOT_ONLINE,
        trusted_channel: bool = True,
    ) -> RestoredState:
        """Establish first trust in S0; atomic write of state + initialized.

        ``trusted_channel`` must be True. A Planner-supplied candidate passed
        with ``trusted_channel=False`` is rejected as SNAPSHOT_UNTRUSTED even
        when its Ed25519 signature is valid (design §5.5 / M07d). The snapshot's
        freshness comes from the caller's trusted path (BOOT-ONLINE TLS pull or
        BOOT-OFFLINE trusted provisioning), NOT from signature verification.
        """
        st = self.state()
        if st == STATE_S1_RESTORE:
            raise StateAlreadyInitialized()
        if st == STATE_S2_CORRUPT:
            raise StateUnavailable()
        # Bootstrap exception: no HWM yet -> version-advance check disabled.
        validate_snapshot(
            snapshot,
            trusted_keys=trusted_keys,
            trusted_issuer=trusted_issuer,
            now=now,
            high_water_version=None,
            trusted_channel=trusted_channel,
            require_version_advance=False,
        )
        cached_text = canonical_json_bytes(dict(snapshot)).decode("utf-8")
        digest_text = snapshot_digest(snapshot)
        version = int(snapshot["version"])
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            # Re-check inside the transaction: another process may have won.
            row = con.execute(
                "SELECT value FROM meta WHERE key='initialized'"
            ).fetchone()
            if row is not None and row[0] == "1":
                con.rollback()
                raise StateAlreadyInitialized()
            con.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('initialized','1')"
            )
            con.execute(
                "INSERT OR REPLACE INTO meta(key,value) VALUES('bootstrap_mode',?)",
                (bootstrap_mode,),
            )
            con.execute(
                "INSERT OR REPLACE INTO snapshot_state"
                "(id,high_water_version,cached_snapshot,cached_digest,bootstrap_mode,"
                "last_refresh_local) VALUES(1,?,?,?,?,?)",
                (version, cached_text, digest_text, bootstrap_mode, float(now)),
            )
            con.commit()
        except Exception:
            try:
                con.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            con.close()
        return RestoredState(
            version, dict(snapshot), digest_text, bootstrap_mode, float(now)
        )

    # ---- candidate acceptance (S1 only) ----

    def accept_candidate(
        self,
        snapshot: Mapping[str, Any],
        *,
        trusted_keys: Mapping[str, Ed25519PublicKey],
        trusted_issuer: str,
        now: float,
        trusted_channel: bool = True,
    ) -> RestoredState:
        """Validate and atomically commit a refreshed candidate in S1.

        On ANY rejection (validation error, storage error, concurrent
        initialization change) the previously cached snapshot and HWM are left
        byte-for-byte unchanged (design §5.2 poisoning invariant).
        """
        st = self.state()
        if st != STATE_S1_RESTORE:
            # S0 (no trusted initial state) and S2 both fail closed.
            raise StateUnavailable()
        # Do NOT serialize/digest before validation: a malformed candidate (e.g.
        # non-finite float) must be rejected with the frozen SNAPSHOT_MALFORMED
        # code from validate_snapshot, never with a raw canonical-JSON ValueError.
        con = self._connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT value FROM meta WHERE key='initialized'"
            ).fetchone()
            if row is None or row[0] != "1":
                con.rollback()
                raise StateUnavailable()
            srow = con.execute(
                "SELECT high_water_version, cached_snapshot, cached_digest, "
                "bootstrap_mode, last_refresh_local FROM snapshot_state WHERE id=1"
            ).fetchone()
            restored = self._validate_row(srow) if srow is not None else None
            if restored is None:
                con.rollback()
                raise StateUnavailable()
            # Version check uses the PERSISTED HWM inside the same transaction.
            validate_snapshot(
                snapshot,
                trusted_keys=trusted_keys,
                trusted_issuer=trusted_issuer,
                now=now,
                high_water_version=restored.high_water_version,
                require_version_advance=True,
                trusted_channel=trusted_channel,
            )
            # Serialization happens only AFTER the candidate is fully accepted.
            cached_text = canonical_json_bytes(dict(snapshot)).decode("utf-8")
            digest_text = snapshot_digest(snapshot)
            version = int(snapshot["version"])
            new_hwm = max(restored.high_water_version, version)
            con.execute(
                "UPDATE snapshot_state SET high_water_version=?, cached_snapshot=?, "
                "cached_digest=?, last_refresh_local=? WHERE id=1",
                (new_hwm, cached_text, digest_text, float(now)),
            )
            con.commit()
        except SnapshotValidationError:
            try:
                con.rollback()
            except sqlite3.Error:
                pass
            raise
        except Exception:
            try:
                con.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            con.close()
        return RestoredState(
            new_hwm, dict(snapshot), digest_text, restored.bootstrap_mode, float(now)
        )

    # ---- test-only corruption helpers (operate on the module's own storage) ----

    def corrupt_cached_snapshot_for_test(self) -> None:
        con = self._connect()
        try:
            con.execute(
                "UPDATE snapshot_state SET cached_snapshot='{CORRUPTED}' WHERE id=1"
            )
            con.commit()
        finally:
            con.close()

    def corrupt_digest_for_test(self) -> None:
        con = self._connect()
        try:
            con.execute(
                "UPDATE snapshot_state SET cached_digest='sha256:deadbeef' WHERE id=1"
            )
            con.commit()
        finally:
            con.close()

    def delete_snapshot_row_for_test(self) -> None:
        con = self._connect()
        try:
            con.execute("DELETE FROM snapshot_state WHERE id=1")
            con.commit()
        finally:
            con.close()

    def is_initialized(self) -> bool:
        con = self._connect()
        try:
            row = con.execute(
                "SELECT value FROM meta WHERE key='initialized'"
            ).fetchone()
            return row is not None and row[0] == "1"
        finally:
            con.close()
