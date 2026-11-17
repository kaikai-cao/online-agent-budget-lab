"""E1.4 transport bridge to the long-lived D11 JSON Lines service (E1.0 §B).

This module is a *transport only*. It owns one long-lived ``subprocess.Popen``
of the frozen Rust ``e1_service`` binary, serialises one JSON request/response
pair at a time on the pipe, correlates by ``request_id``, and detects timeout,
EOF and non-zero child exit. It performs no proof verification and computes no
digest: those remain in the frozen Rust coordinator and in :mod:`e1_runtime`.

Trust and logging rules (E1.0 §B / E1.4 task A):

* The child is spawned with ``command`` (e.g. ``[e1_service_exe, config_path]``).
  The Coordinator signing key lives ONLY in that on-disk config; it is never
  placed in a JSON Lines request or a CLI value handled by this module.
* Prover private witness, private keys and full credentials are never written
  to logs. Only method names, request ids and stable service error codes are
  logged; request/response payloads are never logged.
* On any uncertain failure (timeout, EOF, non-zero exit, response-id
  mismatch) the bridge marks itself unavailable and never silently re-sends
  the business request. An uncertain failure specifically on
  ``submit_transition_e1`` also arms the recovery gate: submits are refused
  until a successful :meth:`get_operation` proves whether the prior operation
  committed. The gate survives both :meth:`restart` and :meth:`start` (a
  restart via ``start()`` must not bypass recovery); only :meth:`get_operation`
  clears it. A well-formed ``ok:false`` (``ServiceError``) is a definitive
  service rejection, not a transport fault, and does not arm the gate.

Windows note: ``selectors`` cannot watch a subprocess pipe reliably, so a
dedicated reader thread feeds a :class:`queue.Queue` and reads use a bounded
``Queue.get(timeout=...)``.
"""

from __future__ import annotations

import json
import logging
import queue
import subprocess
import threading
import time
import uuid
from collections import deque
from typing import Any, Deque, Mapping, Sequence

_LOG = logging.getLogger(__name__)

# A response-id mismatch or EOF is treated as a protocol fault, never as a
# successful answer. These sentinels keep the reader thread's contract explicit.
_EOF = object()


class CrossLayerBridgeError(RuntimeError):
    """Base class for all transport-layer failures."""


class BridgeUnavailable(CrossLayerBridgeError):
    """Service is not usable; no business request was (re)sent."""


class BridgeTimeout(BridgeUnavailable):
    """No matching response arrived within the deadline (outcome uncertain)."""


class BridgeEOF(BridgeUnavailable):
    """Child closed stdout before a response (outcome uncertain)."""


class BridgeProcessExited(BridgeUnavailable):
    """Child exited with a non-zero status (outcome uncertain)."""


class BridgeProtocolError(BridgeUnavailable):
    """A response could not be matched to its request (never trusted)."""


class ServiceError(CrossLayerBridgeError):
    """A well-formed ``ok:false`` response with a stable service error code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"e1_service error {code}: {message}")


class CrossLayerBridge:
    """One long-lived JSON Lines child process, one request in flight at a time.

    Args:
        command: argv used to spawn the service. The final argument is normally
            the trusted config path; private keys never enter this object's
            request payloads.
        timeout: per-request read deadline in seconds.
        startup_timeout: deadline for the initial ``health`` probe.
        max_stderr_lines: bounded capture of child diagnostics (never logged by
            default, available via :meth:`diagnostics` for exit triage only).
    """

    def __init__(
        self,
        command: Sequence[str],
        *,
        timeout: float = 30.0,
        startup_timeout: float = 30.0,
        max_stderr_lines: int = 32,
    ) -> None:
        if not command or not all(isinstance(part, str) for part in command):
            raise ValueError("command must be a non-empty sequence of strings")
        if timeout <= 0 or startup_timeout <= 0:
            raise ValueError("timeouts must be positive")
        self._command = list(command)
        self._timeout = float(timeout)
        self._startup_timeout = float(startup_timeout)
        self._max_stderr_lines = int(max_stderr_lines)

        self._lock = threading.RLock()  # serialises one request/response pair
        self._state_lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._reader: threading.Thread | None = None
        self._stderr_drain: threading.Thread | None = None
        self._queue: queue.Queue[Any] = queue.Queue()
        self._stderr_lines: Deque[str] = deque(maxlen=self._max_stderr_lines)
        self._available = False
        self._must_recover = False
        self._exit_code: int | None = None
        self._closed = False
        self._counter = 0

    # ------------------------------------------------------------------ state //
    @property
    def available(self) -> bool:
        with self._state_lock:
            return self._available

    @property
    def exit_code(self) -> int | None:
        with self._state_lock:
            return self._exit_code

    @property
    def must_recover(self) -> bool:
        """True after a restart or uncertain submit, until ``get_operation`` succeeds."""
        with self._state_lock:
            return self._must_recover

    def diagnostics(self) -> dict[str, Any]:
        """Exit triage only: process state and bounded stderr tail.

        Diagnostics are never written to the application log by this module.
        Callers must not forward raw lines that could contain secrets.
        """
        with self._state_lock:
            return {
                "available": self._available,
                "exit_code": self._exit_code,
                "must_recover": self._must_recover,
                "stderr_tail": list(self._stderr_lines),
            }

    def mark_unavailable(self, reason: str) -> None:
        """Fail-closed: remember that the current process cannot be trusted."""
        with self._state_lock:
            self._available = False
        _LOG.warning("bridge marked unavailable: %s", reason)

    # -------------------------------------------------------------- lifecycle //
    def start(self) -> None:
        """Spawn the child and confirm readiness with a ``health`` probe."""
        with self._lock:
            if self._closed:
                raise BridgeUnavailable("bridge is closed")
            if self._available and self._proc is not None and self._proc.poll() is None:
                return
            self._spawn()
            # Probe with the (shorter) startup deadline; a bad config exits 2.
            self._request("health", {}, timeout=self._startup_timeout)
            # Do NOT clear a recovery gate here. An uncertain D11 submit must
            # stay gated even if the caller reconnects via start() instead of
            # restart(); only a successful get_operation() may clear it.
            _LOG.info("e1_service ready")

    def _spawn(self) -> None:
        self._clear_process()
        try:
            proc = subprocess.Popen(  # noqa: S603 - command is trusted config
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise BridgeUnavailable(f"cannot spawn e1_service: {exc}") from exc
        self._proc = proc
        self._queue = queue.Queue()
        self._reader = threading.Thread(
            target=self._read_stdout, args=(proc, self._queue), name="e1-bridge-reader", daemon=True
        )
        self._stderr_drain = threading.Thread(
            target=self._drain_stderr, args=(proc,), name="e1-bridge-stderr", daemon=True
        )
        with self._state_lock:
            self._available = True
            self._exit_code = None
        self._reader.start()
        self._stderr_drain.start()

    def _clear_process(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        if proc.poll() is None:
            try:
                if proc.stdin is not None:
                    proc.stdin.close()
            except OSError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    pass

    def restart(self) -> None:
        """Obtain a fresh process. Submit is gated until ``get_operation`` runs.

        A restart regenerates the Rust prover/verifier parameters (process-level
        ``OnceLock``), so any proof from the old process must not be re-used with
        the new one without regeneration.
        """
        with self._lock:
            self._clear_process()
            self._spawn()
            with self._state_lock:
                self._must_recover = True  # force get_operation before re-submit
            _LOG.info("e1_service restarted; recovery check required")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._clear_process()
            with self._state_lock:
                self._available = False

    def __enter__(self) -> "CrossLayerBridge":
        self.start()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ------------------------------------------------------------ reader side //
    def _read_stdout(self, proc: subprocess.Popen, out: queue.Queue[Any]) -> None:
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").strip()
                if line:
                    out.put(line)
        except (OSError, ValueError):
            pass
        finally:
            out.put(_EOF)
            code = proc.poll()
            if code is None:
                try:
                    code = proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    code = None
            with self._state_lock:
                if code is not None:
                    self._exit_code = code
                self._available = False
            # Release pipe handles when the child exits on its own; close() and
            # _clear_process() are idempotent about already-closed files.
            for pipe in (proc.stdout, proc.stderr, proc.stdin):
                if pipe is not None:
                    try:
                        pipe.close()
                    except OSError:
                        pass

    def _drain_stderr(self, proc: subprocess.Popen) -> None:
        try:
            assert proc.stderr is not None
            for raw in proc.stderr:
                line = raw.decode("utf-8", errors="replace").rstrip()
                self._stderr_lines.append(line)
        except (OSError, ValueError):
            pass

    # ------------------------------------------------------------ request side //
    def _next_id(self) -> str:
        with self._state_lock:
            self._counter += 1
            n = self._counter
        return f"e14-{uuid.uuid4().hex[:8]}-{n}"

    def _request(
        self,
        method: str,
        payload: Mapping[str, Any],
        *,
        timeout: float | None = None,
        allow_null_result: bool = False,
    ) -> dict[str, Any] | None:
        """Send one request; arm the recovery gate on an uncertain D11 submit.

        E1.0 §B.6: any uncertain fault on ``submit_transition_e1`` (timeout,
        EOF, non-zero exit, write failure, response mismatch) leaves the D11
        commit outcome unknown. Gate future submits until ``get_operation``
        resolves it. ``ServiceError`` is a well-formed rejection, NOT a
        transport fault, so it is deliberately not caught here.
        """
        try:
            return self._request_once(
                method, payload, timeout=timeout, allow_null_result=allow_null_result
            )
        except BridgeUnavailable:
            if method == "submit_transition_e1":
                with self._state_lock:
                    self._must_recover = True
                _LOG.warning("uncertain submit result: recovery gate armed")
            raise

    def _request_once(
        self,
        method: str,
        payload: Mapping[str, Any],
        *,
        timeout: float | None = None,
        allow_null_result: bool = False,
    ) -> dict[str, Any] | None:
        deadline_budget = self._timeout if timeout is None else float(timeout)
        with self._lock:
            with self._state_lock:
                if self._closed:
                    raise BridgeUnavailable("bridge is closed")
                if not self._available or self._proc is None:
                    raise BridgeUnavailable("service is not running; call start() or restart()")
                proc = self._proc
            if proc.poll() is not None:
                self.mark_unavailable("child already exited before request")
                raise BridgeProcessExited(f"child exited with status {proc.returncode}")

            rid = self._next_id()
            envelope = {"request_id": rid, "method": method, "payload": dict(payload)}
            line = json.dumps(envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            assert proc.stdin is not None
            try:
                proc.stdin.write((line + "\n").encode("utf-8"))
                proc.stdin.flush()
            except (OSError, BrokenPipeError) as exc:
                self.mark_unavailable("stdin write failed")
                raise BridgeUnavailable(f"cannot send request: {exc}") from exc

            _LOG.info("bridge request method=%s request_id=%s", method, rid)
            deadline = time.monotonic() + deadline_budget
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.mark_unavailable(f"timeout waiting for {method}")
                    raise BridgeTimeout(f"no response for request_id={rid}")
                try:
                    item = self._queue.get(timeout=remaining)
                except queue.Empty:
                    self.mark_unavailable(f"timeout waiting for {method}")
                    raise BridgeTimeout(f"no response for request_id={rid}") from None
                if item is _EOF:
                    self.mark_unavailable("stdout EOF while awaiting response")
                    with self._state_lock:
                        code = self._exit_code
                    if code not in (None, 0):
                        raise BridgeProcessExited(f"child exited with status {code}")
                    raise BridgeEOF("child closed stdout before responding")
                try:
                    response = json.loads(item)
                except (TypeError, ValueError) as exc:
                    self.mark_unavailable("non-JSON response")
                    raise BridgeProtocolError("response is not JSON") from exc
                if not isinstance(response, dict):
                    self.mark_unavailable("response envelope is not an object")
                    raise BridgeProtocolError("response envelope is not an object")
                if response.get("request_id") != rid:
                    # Serialised pipe means any mismatch is a fault; never bind
                    # a response to a different business request.
                    self.mark_unavailable("response request_id mismatch")
                    raise BridgeProtocolError(
                        f"response request_id {response.get('request_id')!r} != {rid!r}"
                    )
                ok = response.get("ok")
                if ok is True:
                    result = response.get("result")
                    if result is None and allow_null_result:
                        _LOG.info("bridge response ok(null) request_id=%s", rid)
                        return None
                    if not isinstance(result, dict):
                        self.mark_unavailable("success result is not an object")
                        raise BridgeProtocolError("success result is not an object")
                    _LOG.info("bridge response ok request_id=%s", rid)
                    return result
                if ok is False:
                    error = response.get("error")
                    if not isinstance(error, dict):
                        self.mark_unavailable("error envelope is not an object")
                        raise BridgeProtocolError("error envelope is not an object")
                    code = str(error.get("code", "STORE_ERROR"))
                    message = str(error.get("message", ""))
                    # A well-formed service rejection is NOT a transport fault:
                    # the process is still healthy, so do not mark unavailable.
                    _LOG.info("bridge response error request_id=%s code=%s", rid, code)
                    raise ServiceError(code, message)
                self.mark_unavailable("response ok flag missing")
                raise BridgeProtocolError("response missing ok flag")

    # ---------------------------------------------------------------- methods //
    def health(self) -> dict[str, Any]:
        result = self._request("health", {})
        assert result is not None
        return result

    def register_e1(
        self, binding_record: Mapping[str, Any], registration_authorization_b64: str
    ) -> dict[str, Any]:
        result = self._request(
            "register_e1",
            {
                "binding_record": dict(binding_record),
                "registration_authorization_b64": registration_authorization_b64,
            },
        )
        assert result is not None
        return result

    def prove(self, witness: Mapping[str, Any]) -> dict[str, Any]:
        result = self._request("prove", dict(witness))
        assert result is not None
        return result

    def submit_transition_e1(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        with self._state_lock:
            must_recover = self._must_recover
        if must_recover:
            raise BridgeUnavailable(
                "must call get_operation after restart before re-submitting"
            )
        result = self._request("submit_transition_e1", payload)
        assert result is not None
        return result

    def get_operation(
        self, *, operation_id: str, binding_digest: str, metering_quote_digest: str
    ) -> dict[str, Any] | None:
        result = self._request(
            "get_operation",
            {
                "operation_id": operation_id,
                "expected_binding_digest": binding_digest,
                "expected_metering_quote_digest": metering_quote_digest,
            },
            allow_null_result=True,
        )
        # A successful lookup closes the post-restart recovery gate: the caller
        # now knows whether the operation committed (a null result means D11
        # never committed), so a subsequent re-submit is no longer blind.
        with self._state_lock:
            self._must_recover = False
        return result or None


__all__ = [
    "CrossLayerBridge",
    "CrossLayerBridgeError",
    "BridgeUnavailable",
    "BridgeTimeout",
    "BridgeEOF",
    "BridgeProcessExited",
    "BridgeProtocolError",
    "ServiceError",
]
