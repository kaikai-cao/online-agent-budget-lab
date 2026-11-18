"""Executor-side typed client for the independent Journal Service (E1.9-C / C1).

This is a thin adapter over the E1.9-B ``NamedPipeClient.call(method, params)``
IPC.  It does NOT reimplement any of the frozen Journal Service logic: no direct
SQLite access, no journal signing key, no Receipt verification of its own.  The
service remains the sole authority; this client only translates responses into
typed results or structured exceptions.

Production transport is the real Windows Named Pipe (``NamedPipeClient``), which
carries the caller's OS identity via ImpersonateNamedPipeClient (E0 §9.1).  Tests
may inject ``InProcessChannel`` (same ``call`` interface) explicitly; that path
is never selected by production code and must not be described as a security
boundary (E0 §9.3 / constraint 10).
"""

from __future__ import annotations

from typing import Any, Mapping, Protocol


class JournalClientError(Exception):
    """A structured Journal Service rejection (carries the service error code)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Channel(Protocol):
    def call(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]: ...


class JournalClient:
    """Typed, fail-closed wrapper around the E1.9-B six-method IPC API."""

    def __init__(self, channel: Channel, *, executor_id: str) -> None:
        if not isinstance(executor_id, str) or not executor_id:
            raise ValueError("executor_id must be a non-empty string")
        self._channel = channel
        self.executor_id = executor_id

    @classmethod
    def for_pipe(cls, pipe_name: str, *, executor_id: str, connect_retries: int = 100):
        """Production constructor: real Named Pipe, OS-backed server identity."""
        from .journal_ipc import NamedPipeClient

        return cls(NamedPipeClient(pipe_name, connect_retries=connect_retries), executor_id=executor_id)

    def _call(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        resp = self._channel.call(method, dict(params))
        if not isinstance(resp, Mapping) or "ok" not in resp:
            raise JournalClientError("BAD_RESPONSE", f"malformed IPC response for {method}")
        if not resp["ok"]:
            err = resp.get("error") or {}
            if not isinstance(err, Mapping):
                err = {}
            raise JournalClientError(str(err.get("code", "UNKNOWN")), str(err.get("message", "service error")))
        result = resp.get("result")
        if not isinstance(result, Mapping):
            raise JournalClientError("BAD_RESPONSE", f"missing result for {method}")
        return dict(result)

    # -- six API wrappers -------------------------------------------------------

    def verify_integrity(self) -> int:
        result = self._call("verify_integrity", {})
        count = result.get("verified_entries")
        if isinstance(count, bool) or not isinstance(count, int):
            raise JournalClientError("BAD_RESPONSE", "verified_entries must be an int")
        return count

    def append_intent(self, *, operation_id: str, binding_digest: str) -> dict[str, Any]:
        """Append INTENT; envelope is the frozen three-field INTENT object.

        The executor_id is supplied as a *claim*; the service authorises it
        against the fixed OS-identity mapping (E0 §9.1 constraint 2).  The client
        can never choose a trusted identity or public key.
        """
        envelope = {
            "operation_id": operation_id,
            "binding_digest": binding_digest,
            "executor_id": self.executor_id,
        }
        result = self._call("append_intent", {
            "operation_id": operation_id,
            "executor_id": self.executor_id,
            "envelope": envelope,
        })
        return self._entry_result(result, expected_phase="INTENT")

    def append_result(self, *, operation_id: str, binding_digest: str, result_value: Any,
                      execution_receipt: Mapping[str, Any]) -> dict[str, Any]:
        """Append RESULT bound to the ORIGINAL signed receipt (never rebuilt)."""
        envelope = {
            "operation_id": operation_id,
            "binding_digest": binding_digest,
            "result": result_value,
            "execution_receipt": dict(execution_receipt),
        }
        result = self._call("append_result", {
            "operation_id": operation_id,
            "executor_id": self.executor_id,
            "envelope": envelope,
        })
        return self._entry_result(result, expected_phase="RESULT")

    def get_entry(self, *, operation_id: str, phase: str) -> dict[str, Any] | None:
        """Return the signed entry, or None on NOT_FOUND."""
        if phase not in ("INTENT", "RESULT"):
            raise ValueError("phase must be INTENT or RESULT")
        try:
            result = self._call("get_entry", {"operation_id": operation_id, "phase": phase})
        except JournalClientError as exc:
            if exc.code == "NOT_FOUND":
                return None
            raise
        entry = result.get("entry")
        if not isinstance(entry, Mapping):
            raise JournalClientError("BAD_RESPONSE", "get_entry returned no entry")
        return dict(entry)

    def get_checkpoint(self, *, seq: int) -> dict[str, Any] | None:
        """Return the historical checkpoint at ``seq``, or None on NOT_FOUND."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise ValueError("seq must be a positive int")
        try:
            result = self._call("get_checkpoint", {"seq": seq})
        except JournalClientError as exc:
            if exc.code == "NOT_FOUND":
                return None
            raise
        cp = result.get("checkpoint")
        if not isinstance(cp, Mapping):
            raise JournalClientError("BAD_RESPONSE", "get_checkpoint returned no checkpoint")
        return dict(cp)

    def get_head(self) -> dict[str, Any]:
        result = self._call("get_head", {})
        cp = result.get("checkpoint")
        if not isinstance(cp, Mapping):
            raise JournalClientError("BAD_RESPONSE", "get_head returned no checkpoint")
        return dict(cp)

    def get_entries_from(self, *, seq: int) -> list[dict[str, Any]]:
        """E1.9-C.1: signed entries with seq >= ``seq`` (read-only replay API).

        The service selects/orders by SIGNED seq and verifies every signature
        before returning.  An empty list means the cursor is already at head.
        """
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise ValueError("seq must be a positive int")
        result = self._call("get_entries_from", {"seq": seq})
        entries = result.get("entries")
        if not isinstance(entries, list) or not all(isinstance(e, Mapping) for e in entries):
            raise JournalClientError("BAD_RESPONSE", "get_entries_from returned no entry list")
        return [dict(e) for e in entries]

    # -- helpers ----------------------------------------------------------------

    @staticmethod
    def _entry_result(result: Mapping[str, Any], *, expected_phase: str) -> dict[str, Any]:
        entry = result.get("entry")
        if not isinstance(entry, Mapping):
            raise JournalClientError("BAD_RESPONSE", "append returned no entry")
        if entry.get("phase") != expected_phase:
            raise JournalClientError("BAD_RESPONSE", f"append returned wrong phase {entry.get('phase')!r}")
        idempotent = result.get("idempotent")
        if not isinstance(idempotent, bool):
            raise JournalClientError("BAD_RESPONSE", "append returned non-bool idempotent")
        return {"entry": dict(entry), "idempotent": idempotent}
