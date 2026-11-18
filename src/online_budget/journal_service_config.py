"""E1.9-B -- Journal Service configuration (fixed registries).

This module holds the immutable, deployment-time configuration of the
independent Journal Service:

  * ``os_identity -> allowed executor_id`` mapping (B.3 OS identity binding);
  * ``executor_id -> public_key`` registry (B.3/B.4 Receipt signature root);
  * the pipe name, the frozen Journal DB path and the service-owned idempotency
    DB path.

Design rules (E1.9-B2 design doc, B2.1/B2.2):
  * the registries are initialised by ``ADMIN`` at deploy time and are FIXED for
    the lifetime of the process.  There is deliberately NO runtime API to add,
    replace or upload a key or identity mapping -- a client cannot smuggle in
    its own public key;
  * an OS identity may map to exactly one ``executor_id`` (recommended) or to a
    whitelist of several; the request-supplied ``executor_id`` is a *claim* that
    must be checked against this mapping -- it is never an authenticated fact;
  * no mapping / no public key -> fail closed.

This module never opens a database or performs IO beyond parsing; it only
validates configuration shape and exposes immutable views.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import b64decode, public_key_from_b64, public_key_digest, is_sha256


class ServiceConfigError(ValueError):
    """Raised when a deployment configuration is invalid or incomplete."""


@dataclass(frozen=True)
class ServiceConfig:
    """Immutable service configuration with pre-parsed Ed25519 public keys."""

    pipe_name: str
    journal_db_path: Path
    idempotency_db_path: Path
    journal_signing_key_b64: str
    journal_verify_key_b64: str
    allowed_client_sids: tuple[str, ...]
    os_identity_to_executor_ids: Mapping[str, frozenset[str]]
    executor_public_keys: Mapping[str, Ed25519PublicKey]
    # B-F2 private-file isolation.  Empty means "not configured": the service
    # prints a warning instead of silently assuming the ACL is safe.
    journal_service_sid: str = ""
    executor_account_sids: tuple[str, ...] = ()

    # -- constructors -----------------------------------------------------------
    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, base_dir: str | Path | None = None) -> "ServiceConfig":
        """Parse and validate a deployment config mapping.

        Expected keys::

            pipe_name                    str
            journal_db_path              str (path)
            idempotency_db_path          str (path)
            journal_signing_key_b64      str (base64, 32-byte Ed25519 seed)
            journal_verify_key_b64       str (base64, 32-byte Ed25519 pubkey)
            allowed_client_sids          list[str]  (SID strings for the pipe ACL)
            os_identity_to_executor_ids  dict[str, list[str]]
            executor_public_keys         dict[str, str(base64 pubkey)]
            journal_service_sid          str  (optional, B-F2: service account SID owning key/DB)
            executor_account_sids        list[str]  (optional, B-F2: SIDs denied key/DB access)
        """
        if not isinstance(data, Mapping):
            raise ServiceConfigError("config must be a mapping")
        root = Path(base_dir) if base_dir is not None else Path(".")

        pipe_name = data.get("pipe_name")
        if not isinstance(pipe_name, str) or not pipe_name or "\\" in pipe_name:
            raise ServiceConfigError("pipe_name must be a non-empty string without backslashes")

        def _path(key: str) -> Path:
            value = data.get(key)
            if not isinstance(value, str) or not value:
                raise ServiceConfigError(f"{key} must be a non-empty path string")
            p = Path(value)
            return p if p.is_absolute() else root / p

        journal_path = _path("journal_db_path")
        idem_path = _path("idempotency_db_path")
        if journal_path == idem_path:
            raise ServiceConfigError("journal_db_path and idempotency_db_path must differ")

        sign_b64 = data.get("journal_signing_key_b64")
        verify_b64 = data.get("journal_verify_key_b64")
        for key, value in (("journal_signing_key_b64", sign_b64), ("journal_verify_key_b64", verify_b64)):
            if not isinstance(value, str) or not value:
                raise ServiceConfigError(f"{key} must be a non-empty base64 string")
            try:
                raw = b64decode(value)
            except Exception as exc:  # noqa: BLE001 - surface config error
                raise ServiceConfigError(f"{key} is not valid base64: {exc}") from exc
            if len(raw) != 32:
                raise ServiceConfigError(f"{key} must decode to 32 bytes")

        sids = data.get("allowed_client_sids")
        if not isinstance(sids, (list, tuple)) or not sids or not all(isinstance(s, str) and s for s in sids):
            raise ServiceConfigError("allowed_client_sids must be a non-empty list of SID strings")

        raw_map = data.get("os_identity_to_executor_ids")
        if not isinstance(raw_map, Mapping) or not raw_map:
            raise ServiceConfigError("os_identity_to_executor_ids must be a non-empty mapping")
        identity_map: dict[str, frozenset[str]] = {}
        for os_identity, exec_ids in raw_map.items():
            if not isinstance(os_identity, str) or not os_identity:
                raise ServiceConfigError("OS identity keys must be non-empty strings")
            if not isinstance(exec_ids, (list, tuple)) or not exec_ids or not all(
                isinstance(e, str) and e for e in exec_ids
            ):
                raise ServiceConfigError(f"executor id list for {os_identity!r} must be non-empty strings")
            identity_map[os_identity] = frozenset(exec_ids)

        raw_keys = data.get("executor_public_keys")
        if not isinstance(raw_keys, Mapping) or not raw_keys:
            raise ServiceConfigError("executor_public_keys must be a non-empty mapping")
        pubkeys: dict[str, Ed25519PublicKey] = {}
        for exec_id, key_b64 in raw_keys.items():
            if not isinstance(exec_id, str) or not exec_id:
                raise ServiceConfigError("executor public-key ids must be non-empty strings")
            if not isinstance(key_b64, str) or not key_b64:
                raise ServiceConfigError(f"public key for {exec_id!r} must be a base64 string")
            try:
                pubkeys[exec_id] = public_key_from_b64(key_b64)
            except Exception as exc:  # noqa: BLE001
                raise ServiceConfigError(f"public key for {exec_id!r} is invalid: {exc}") from exc

        # Every executor_id referenced by the identity map must have a registry key.
        referenced = set().union(*identity_map.values())
        missing = referenced - set(pubkeys)
        if missing:
            raise ServiceConfigError(f"identity map references executor ids without a public key: {sorted(missing)}")

        # B-F2 optional private-file isolation settings.  Absent fields are OK
        # (backward compatible) but the service then warns instead of claiming
        # the file ACL boundary is enforced.
        svc_sid = data.get("journal_service_sid", "")
        if not isinstance(svc_sid, str):
            raise ServiceConfigError("journal_service_sid must be a string when present")
        raw_exec_sids = data.get("executor_account_sids", [])
        if not isinstance(raw_exec_sids, (list, tuple)) or not all(
            isinstance(s, str) and s for s in raw_exec_sids
        ):
            raise ServiceConfigError("executor_account_sids must be a list of SID strings when present")

        return cls(
            pipe_name=pipe_name,
            journal_db_path=journal_path,
            idempotency_db_path=idem_path,
            journal_signing_key_b64=sign_b64,
            journal_verify_key_b64=verify_b64,
            allowed_client_sids=tuple(sids),
            os_identity_to_executor_ids=identity_map,
            executor_public_keys=pubkeys,
            journal_service_sid=svc_sid,
            executor_account_sids=tuple(raw_exec_sids),
        )

    # -- helpers ----------------------------------------------------------------
    def public_key_for(self, executor_id: str) -> Ed25519PublicKey:
        """Look up the fixed public key for an executor id; fail closed."""
        key = self.executor_public_keys.get(executor_id)
        if key is None:
            raise ServiceConfigError(f"no fixed public key registered for executor_id={executor_id!r}")
        return key

    def public_key_digests(self) -> dict[str, str]:
        """Return ``executor_id -> sha256 fingerprint`` for reporting/audit."""
        return {eid: public_key_digest(key) for eid, key in self.executor_public_keys.items()}

    def redacted_dict(self) -> dict[str, Any]:
        """Return a report-safe view (no private key material)."""
        return {
            "pipe_name": self.pipe_name,
            "journal_db_path": str(self.journal_db_path),
            "idempotency_db_path": str(self.idempotency_db_path),
            "allowed_client_sids": list(self.allowed_client_sids),
            "os_identity_to_executor_ids": {
                k: sorted(v) for k, v in self.os_identity_to_executor_ids.items()
            },
            "executor_public_key_fingerprints": self.public_key_digests(),
            "journal_service_sid": self.journal_service_sid,
            "executor_account_sids": list(self.executor_account_sids),
        }


__all__ = ["ServiceConfig", "ServiceConfigError"]
