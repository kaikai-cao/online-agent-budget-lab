"""E1.9-B -- independent Journal Service (B.1 + B.4 + B.5 orchestration).

The service is a standalone process that OWNS the Journal DB and its signing
key.  It never exposes the key or the DB to the Executor.  Every security
decision (identity, Receipt v2 validation, idempotency, authoritative seq/chain
state) happens here, server-side.

Lifecycle (B.1):
  * ``start()`` opens the frozen ``AuthorityJournal`` and runs a FULL
    ``verify_integrity()``.  A corrupted log raises ``ServiceStartupError`` and
    the service refuses to enter normal serving state (fail closed).
  * state is read from the persistent DB on every call -- there is no in-memory
    cache of the chain; a restart restores everything from persistence.

Request handling:
  * the caller identity is supplied by the TRANSPORT as a ``CallerIdentity``
    (OS-backed in production), never by the request body;
  * the service validates parameters, authorises identity, enforces Receipt v2
    rules and content-sensitive idempotency, then appends via the frozen core.

This module is transport-agnostic: the Named Pipe layer (``journal_ipc``)
adapts wire requests into ``ServiceRequest`` objects and passes the authenticated
``CallerIdentity``.  Unit tests call the service directly with an injected
identity provider; a real-Windows test drives it through the Named Pipe.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import journal as jmod
from .canonical import b64decode
from .journal_identity import (
    CallerIdentity,
    CallerIdentityError,
    IdentityAuthorizer,
)
from .journal_idempotency import (
    IdempotencyConflict,
    IdempotencyStore,
    find_signed_entry,
    payload_digest_for,
)
from .journal_receipt_validator import ReceiptValidationError, validate_result_receipt
from .journal_service_config import ServiceConfig


class ServiceStartupError(RuntimeError):
    """The service could not start safely (e.g. integrity check failed)."""


class ServiceError(ValueError):
    """A structured service error with a stable code for IPC responses."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ServiceRequest:
    method: str
    params: Mapping[str, Any]


_ALLOWED_METHODS = frozenset(
    {"append_intent", "append_result", "get_entry", "get_checkpoint", "get_head", "verify_integrity"}
)


class JournalService:
    """The authoritative Journal Service core."""

    def __init__(self, config: ServiceConfig, *, require_os_backed: bool = True) -> None:
        self._config = config
        self._authorizer = IdentityAuthorizer(config, require_os_backed=require_os_backed)
        signing_key = self._load_signing_key(config.journal_signing_key_b64)
        verify_key = self._load_verify_key(config.journal_verify_key_b64)
        self._journal = jmod.AuthorityJournal(
            config.journal_db_path, signing_key=signing_key, verify_key=verify_key
        )
        self._idem = IdempotencyStore(config.idempotency_db_path)
        self._running = False

    @staticmethod
    def _load_signing_key(value: str) -> Ed25519PrivateKey:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            return Ed25519PrivateKey.from_private_bytes(b64decode(value))
        except Exception as exc:  # noqa: BLE001
            raise ServiceStartupError(f"invalid journal signing key: {exc}") from exc

    @staticmethod
    def _load_verify_key(value: str):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        try:
            return Ed25519PublicKey.from_public_bytes(b64decode(value))
        except Exception as exc:  # noqa: BLE001
            raise ServiceStartupError(f"invalid journal verify key: {exc}") from exc

    # -- lifecycle --------------------------------------------------------------
    def start(self) -> "JournalService":
        try:
            self._journal.verify_integrity()
        except jmod.JournalIntegrityError as exc:
            raise ServiceStartupError(f"journal integrity check failed at startup: {exc}") from exc
        self._running = True
        return self

    def stop(self) -> None:
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    # -- dispatch ---------------------------------------------------------------
    def handle(self, request: ServiceRequest, caller: CallerIdentity) -> dict[str, Any]:
        if not self._running:
            raise ServiceError("SERVICE_NOT_RUNNING", "service is not in serving state")
        if not isinstance(request, ServiceRequest):
            raise ServiceError("BAD_REQUEST", "request must be a ServiceRequest")
        method = request.method
        if method not in _ALLOWED_METHODS:
            raise ServiceError("UNKNOWN_METHOD", f"unknown method {method!r}")
        params = request.params
        if not isinstance(params, Mapping):
            raise ServiceError("BAD_PARAMS", "params must be a mapping")

        if method == "append_intent":
            return self._append_intent(params, caller)
        if method == "append_result":
            return self._append_result(params, caller)
        if method == "get_entry":
            return self._get_entry(params, caller)
        if method == "get_checkpoint":
            return self._get_checkpoint(params, caller)
        if method == "get_head":
            return self._get_head(caller)
        if method == "verify_integrity":
            return self._verify_integrity(caller)
        raise ServiceError("UNKNOWN_METHOD", f"unhandled method {method!r}")

    # -- writes -----------------------------------------------------------------
    def _append_intent(self, params: Mapping[str, Any], caller: CallerIdentity) -> dict[str, Any]:
        self._require_fields(params, {"operation_id", "envelope", "executor_id"})
        op = self._require_str(params, "operation_id")
        claimed_exec = self._require_str(params, "executor_id")
        envelope = params["envelope"]
        if not isinstance(envelope, Mapping):
            raise ServiceError("BAD_ENVELOPE", "envelope must be a mapping")

        executor_id = self._authorizer.authorize(caller, claimed_exec)
        payload_digest = self._safe_payload_digest("INTENT", envelope)
        # envelope.executor_id must match the authorised claim.
        if envelope.get("executor_id") != executor_id:
            raise ServiceError("EXECUTOR_ID_MISMATCH", "INTENT envelope executor_id != authorised executor_id")

        return self._append_with_idempotency(
            phase="INTENT",
            operation_id=op,
            envelope=envelope,
            payload_digest=payload_digest,
        )

    def _append_result(self, params: Mapping[str, Any], caller: CallerIdentity) -> dict[str, Any]:
        self._require_fields(params, {"operation_id", "envelope", "executor_id"})
        op = self._require_str(params, "operation_id")
        claimed_exec = self._require_str(params, "executor_id")
        envelope = params["envelope"]
        if not isinstance(envelope, Mapping):
            raise ServiceError("BAD_ENVELOPE", "envelope must be a mapping")

        executor_id = self._authorizer.authorize(caller, claimed_exec)
        self._require_fields(envelope, {"operation_id", "binding_digest", "result", "execution_receipt"})
        if envelope.get("operation_id") != op:
            raise ServiceError("OPERATION_ID_MISMATCH", "RESULT envelope operation_id != operation_id")

        # Resolve the authoritative signed INTENT (executor_id + binding_digest)
        # from the Journal, never from the client.
        intent = self._signed_intent_for(op)
        if intent is None:
            raise ServiceError("NO_INTENT", "no signed INTENT for operation_id")
        intent_executor_id = intent["executor_id"]
        intent_binding = intent["envelope"].get("binding_digest")
        if intent_executor_id != executor_id:
            raise ServiceError("EXECUTOR_ID_MISMATCH", "authorised executor_id != INTENT executor_id")

        public_key = self._config.public_key_for(executor_id)
        try:
            validate_result_receipt(
                receipt=envelope["execution_receipt"],
                envelope=envelope,
                intent_executor_id=intent_executor_id,
                intent_binding_digest=intent_binding,
                executor_public_key=public_key,
            )
        except ReceiptValidationError as exc:
            raise ServiceError(exc.code, exc.message) from exc

        payload_digest = self._safe_payload_digest("RESULT", envelope)
        return self._append_with_idempotency(
            phase="RESULT",
            operation_id=op,
            envelope=envelope,
            payload_digest=payload_digest,
        )

    def _append_with_idempotency(
        self, *, phase: str, operation_id: str, envelope: Mapping[str, Any], payload_digest: str
    ) -> dict[str, Any]:
        """Check idempotency, append, and record -- under an authoritative lock."""
        with self._idem.authoritative_write() as idem_con:
            existing = self._idem.get(idem_con, operation_id, phase)
            if existing is not None:
                return self._resolve_idempotent(existing, payload_digest)

            # Authoritative fallback: a prior append may have succeeded while the
            # fast-index write was lost.  Scan the signed Journal before appending.
            signed = find_signed_entry(self._journal, operation_id=operation_id, phase=phase)
            if signed is not None:
                if signed["payload_digest"] != payload_digest:
                    raise ServiceError(
                        "IDEMPOTENCY_CONFLICT", "same (operation_id, phase) with a different payload"
                    )
                self._idem.put(
                    idem_con,
                    operation_id=operation_id,
                    phase=phase,
                    payload_digest=signed["payload_digest"],
                    seq=signed["seq"],
                    entry_digest=signed["entry_digest"],
                )
                return {"entry": signed, "idempotent": True}

            entry = self._journal.append(phase=phase, operation_id=operation_id, envelope=envelope)
            self._idem.put(
                idem_con,
                operation_id=operation_id,
                phase=phase,
                payload_digest=payload_digest,
                seq=entry["seq"],
                entry_digest=entry["entry_digest"],
            )
            return {"entry": entry, "idempotent": False}

    def _resolve_idempotent(self, existing: Mapping[str, Any], payload_digest: str) -> dict[str, Any]:
        if existing["payload_digest"] != payload_digest:
            raise ServiceError("IDEMPOTENCY_CONFLICT", "same (operation_id, phase) with a different payload")
        # Return the original signed entry from the authoritative Journal.
        signed = find_signed_entry(
            self._journal, operation_id=existing["operation_id"], phase=existing["phase"]
        )
        if signed is None or signed["seq"] != existing["seq"] or signed["entry_digest"] != existing["entry_digest"]:
            raise ServiceError("IDEMPOTENCY_STATE", "idempotency index diverges from signed Journal")
        return {"entry": signed, "idempotent": True}

    # -- reads ------------------------------------------------------------------
    def _get_entry(self, params: Mapping[str, Any], caller: CallerIdentity) -> dict[str, Any]:
        self._authorizer.authorize_read(caller)
        self._require_fields(params, {"operation_id", "phase"})
        op = self._require_str(params, "operation_id")
        phase = self._require_str(params, "phase")
        if phase not in {"INTENT", "RESULT"}:
            raise ServiceError("BAD_PHASE", "phase must be INTENT or RESULT")
        entry = find_signed_entry(self._journal, operation_id=op, phase=phase)
        if entry is None:
            raise ServiceError("NOT_FOUND", "no entry for (operation_id, phase)")
        return {"entry": entry}

    def _get_checkpoint(self, params: Mapping[str, Any], caller: CallerIdentity) -> dict[str, Any]:
        self._authorizer.authorize_read(caller)
        self._require_fields(params, {"seq"})
        seq = params["seq"]
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise ServiceError("BAD_SEQ", "seq must be a positive integer")
        try:
            cp = self._journal.checkpoint_at(seq)
        except jmod.JournalError as exc:
            raise ServiceError("NOT_FOUND", str(exc)) from exc
        return {"checkpoint": cp}

    def _get_head(self, caller: CallerIdentity) -> dict[str, Any]:
        self._authorizer.authorize_read(caller)
        try:
            return {"checkpoint": self._journal.head()}
        except jmod.JournalError as exc:
            raise ServiceError("EMPTY_JOURNAL", str(exc)) from exc

    def _verify_integrity(self, caller: CallerIdentity) -> dict[str, Any]:
        self._authorizer.authorize_read(caller)
        try:
            count = self._journal.verify_integrity()
        except jmod.JournalIntegrityError as exc:
            raise ServiceError("INTEGRITY_FAILURE", str(exc)) from exc
        return {"verified_entries": count}

    # -- helpers ----------------------------------------------------------------
    def _signed_intent_for(self, operation_id: str) -> dict[str, Any] | None:
        return find_signed_entry(self._journal, operation_id=operation_id, phase="INTENT")

    def _safe_payload_digest(self, phase: str, envelope: Mapping[str, Any]) -> str:
        try:
            return payload_digest_for(phase, envelope)
        except (ValueError, jmod.JournalError) as exc:
            raise ServiceError("BAD_ENVELOPE", str(exc)) from exc

    @staticmethod
    def _require_fields(mapping: Mapping[str, Any], fields: set[str]) -> None:
        if set(mapping) != fields:
            raise ServiceError(
                "FIELD_SET", f"expected exactly {sorted(fields)}, got {sorted(mapping)}"
            )

    @staticmethod
    def _require_str(mapping: Mapping[str, Any], key: str) -> str:
        value = mapping.get(key)
        if not isinstance(value, str) or not value:
            raise ServiceError("BAD_FIELD", f"{key} must be a non-empty string")
        return value


__all__ = [
    "ServiceRequest",
    "ServiceError",
    "ServiceStartupError",
    "JournalService",
]
