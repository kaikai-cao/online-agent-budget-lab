"""H2 Executor: four authorization/revocation paths with an injected logical clock.

Implements design docs/H2_REVOCATION_DESIGN.md §2/§3/§5.3/§6 and the C2 flow in
§5.4/§5.5. This is a NEW module: H1's ``Executor.execute_c`` uses time.time()
internally and is intentionally NOT modified; H2 reuses H1's protocol, signing,
TLS verifier, and Sink, but implements its own execution entry with an injected
clock so that W_risk/D_prop/age are attributable and reproducible.

Groups (only the "authorization verification + revocation handling" layer differs;
ActionRequest / action_digest / jti / trust anchor / binding / Sink are shared):
- B2: real TCP+TLS online query (H1 B2OnlineVerifier), every exec online, fail
      closed. Records t_query and supports a barrier between query-pass and
      Sink consume for M15 (query->consume TOCTOU).
- C0: Ed25519 offline credential, TTL=300, no revocation layer.
- C1: Ed25519 offline credential, TTL in {5,15,60}; strict issued_at<=now<expires_at.
- C2: Ed25519 offline credential TTL=300 + pre-exec snapshot refresh decision
      (§5.3) + revocation check (§6.2) + persisted HWM/bootstrap (§5.4/§5.5).

Time discipline (design §7.1 / protocol §2): ALL logical timestamps come from
``LogicalClock`` (injected; no sleep). Wall-clock costs use perf_counter and are
kept in separate fields; they NEVER enter a window calculation.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from online_budget.canonical import (
    b64decode,
    canonical_json_bytes,
    is_sha256,
)

# H1 components reused verbatim (no H1 source is edited).
from h1_authorization_service import (
    AuthorizationService,
    AuthServiceTLSServer,
    B2OnlineVerifier,
    _make_self_signed_cert,
)
from h1_executor import VerificationError as H1VerificationError
from h1_protocol import CREDENTIAL_DOMAIN, H1ProtocolError, compute_action_digest
from h1_sink import ControlledSink

from h2_snapshot import (
    SnapshotValidationError,
    build_snapshot,
    normalize_revoked_jtis,
    validate_snapshot,
)
from h2_snapshot_state import (
    BOOT_OFFLINE,
    BOOT_ONLINE,
    STATE_S0_BOOTSTRAP,
    STATE_S1_RESTORE,
    STATE_S2_CORRUPT,
    RestoredState,
    SnapshotStateError,
    SnapshotStateStore,
    StateAlreadyInitialized,
    StateUnavailable,
)

# ---- frozen outcomes / refresh result classes (design §5.3 / protocol §5.3) ----

OUTCOME_EXECUTED = "EXECUTED"
OUTCOME_REJECTED = "REJECTED"
OUTCOME_DEDUP_HIT = "DEDUP_HIT"
OUTCOME_ROLLED_BACK = "ROLLED_BACK"

REFRESH_SUCCESS = "REFRESH_SUCCESS"
REFRESH_FAILED_STALE_CONTINUE = "REFRESH_FAILED_STALE_CONTINUE"
REFRESH_FAILED_FAIL_CLOSED = "REFRESH_FAILED_FAIL_CLOSED"
NO_REFRESH_NEEDED = "NO_REFRESH_NEEDED"

# Frozen rejection reasons (design §5.2 / §6.3; H1 reason strings for the shared
# credential/binding chain are preserved verbatim).
REASON_REVOKED_BY_SNAPSHOT = "REVOKED_BY_SNAPSHOT"
REASON_SNAPSHOT_UNAVAILABLE = "SNAPSHOT_UNAVAILABLE"
REASON_STATE_UNAVAILABLE = "SNAPSHOT_STATE_UNAVAILABLE"
REASON_B2_PREFIX = "B2_DENIED:"


class LogicalClock:
    """Injected logical clock (seconds). No wall-clock/sleep advancement."""

    def __init__(self, t: float = 0.0) -> None:
        self.t = float(t)

    def now(self) -> float:
        return self.t

    def set(self, t: float) -> None:
        self.t = float(t)

    def advance(self, dt: float) -> None:
        self.t += float(dt)


@dataclass
class TrialResult:
    """Standardized per-execution observation record (protocol §5)."""

    group: str = "NA"
    outcome: str = "NA"
    reason: str = "NA"
    effects_added: int = 0
    # injected logical timestamps (s)
    t_issue: float | None = None
    t_revoke: float | None = None
    t_exec_attempt: float | None = None
    t_snapshot_generated: float | None = None
    t_snapshot_obtained: float | None = None
    t_first_reject: float | None = None
    t_last_refresh_local: float | None = None
    t_query: float | None = None
    t_consume: float | None = None
    # refresh classification & counters (§5.3.5 / protocol §5.3, §6.4)
    refresh_outcome: str = "NA"
    refresh_attempts: int = 0
    refresh_latency_ms: float | None = None
    # C2 snapshot observations
    snapshot_version_cached: int | None = None
    snapshot_version_candidate: int | None = None
    snapshot_valid_until: float | None = None
    high_water_version: int | None = None
    snapshot_accepted: bool | None = None
    snapshot_state_ok: bool | None = None
    executor_restarted: bool = False
    initialized: bool | None = None
    bootstrap_mode: str = "NA"
    w_risk_path: str = "NA"
    b2_race_effect_count: int | None = None
    # wall-clock costs (ms, seconds) -- separate time system
    sync_duration_ms: float | None = None
    snapshot_verify_ms: float | None = None
    observation_wall_seconds: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return dict(vars(self))


class H2Executor:
    """Unified execution entry for B2/C0/C1/C2."""

    def __init__(
        self,
        *,
        executor_id: str,
        sink: ControlledSink,
        clock: LogicalClock,
        trusted_keys: Mapping[str, Ed25519PublicKey],
        trusted_issuer: str,
        trusted_audience: str,
        b2_verifier: B2OnlineVerifier | None = None,
        snapshot_state: SnapshotStateStore | None = None,
        refresh_interval: float = 30.0,
        snapshot_fetcher: Callable[[float], dict[str, Any] | None] | None = None,
    ) -> None:
        self.executor_id = executor_id
        self.sink = sink
        self.clock = clock
        self.trusted_keys = dict(trusted_keys)
        self.trusted_issuer = trusted_issuer
        self.trusted_audience = trusted_audience
        self.b2_verifier = b2_verifier
        self.snapshot_state = snapshot_state
        self.R = float(refresh_interval)
        # online fetcher: called with injected logical `now`; returns a candidate
        # snapshot dict or None when the service is unreachable.
        self.snapshot_fetcher = snapshot_fetcher

    # ---- shared verification chain (C0/C1/C2; mirrors H1 execute_c, injected now) ----

    def _recompute_digest(self, request: Mapping[str, Any]) -> str:
        try:
            d = compute_action_digest(request)
        except H1ProtocolError as exc:
            raise H1VerificationError(f"BINDING_CANONICALIZATION_FAILED:{exc}") from exc
        if not is_sha256(d):
            raise H1VerificationError("BINDING_BAD_DIGEST")
        return d

    def _check_binding(self, *, request: Mapping[str, Any], claimed_digest: str) -> str:
        actual = self._recompute_digest(request)
        if request.get("executor_id") != self.executor_id:
            raise H1VerificationError("EXECUTOR_TARGET_MISMATCH")
        if actual != claimed_digest:
            raise H1VerificationError("ACTION_DIGEST_MISMATCH")
        return actual

    def verify_credential(
        self,
        *,
        request: Mapping[str, Any],
        credential: Mapping[str, Any],
        now: float | None = None,
    ) -> tuple[str, str]:
        """Verify an Ed25519 authorization credential with an injected clock.

        Returns (jti, recomputed_action_digest). Rejection reasons match H1's
        execute_c exactly so H2 does not weaken the shared verification chain.
        """
        now = self.clock.now() if now is None else now
        payload = credential.get("payload")
        signature = credential.get("signature")
        if not isinstance(payload, Mapping) or not isinstance(signature, str):
            raise H1VerificationError("C_BAD_CREDENTIAL_SHAPE")
        if payload.get("domain") != CREDENTIAL_DOMAIN:
            raise H1VerificationError("C_BAD_DOMAIN")
        if payload.get("version") != 1:
            raise H1VerificationError("C_BAD_VERSION")
        key_id = payload.get("key_id")
        pub = self.trusted_keys.get(key_id)
        if pub is None:
            raise H1VerificationError("C_UNKNOWN_KEY_ID")
        if payload.get("issuer") != self.trusted_issuer:
            raise H1VerificationError("C_BAD_ISSUER")
        if payload.get("audience") != self.trusted_audience:
            raise H1VerificationError("C_BAD_AUDIENCE")
        try:
            pub.verify(b64decode(signature), canonical_json_bytes(dict(payload)))
        except (ValueError, InvalidSignature) as exc:
            raise H1VerificationError("C_SIGNATURE_INVALID") from exc
        jti = payload.get("jti")
        claimed = payload.get("action_digest")
        if not isinstance(jti, str) or not is_sha256(str(claimed)):
            raise H1VerificationError("C_BAD_CLAIMS")
        if now >= float(payload.get("expires_at", 0)):
            raise H1VerificationError("C_EXPIRED")
        if now < float(payload.get("issued_at", 0)):
            raise H1VerificationError("C_NOT_YET_VALID")
        actual = self._check_binding(request=request, claimed_digest=str(claimed))
        return jti, actual

    # ---- shared downstream: atomic consume + controlled effect ----

    def _consume_and_effect(
        self,
        *,
        jti: str,
        action_digest: str,
        path: str,
        result: TrialResult,
        rollback_once: bool = False,
    ) -> TrialResult:
        before = self.sink.effect_count()
        effect = {
            "status": "EXECUTED",
            "path": path,
            "jti": jti,
            "action_digest": action_digest,
            "executor_id": self.executor_id,
        }
        out = self.sink.consume_and_effect(
            jti=jti,
            action_digest=action_digest,
            path=path,
            result=effect,
            rollback_once=rollback_once,
        )
        result.effects_added = self.sink.effect_count() - before
        # H1 Sink outcomes are authoritative for the shared consumption layer.
        if out["outcome"] == "DEDUP_HIT":
            result.outcome = OUTCOME_DEDUP_HIT
        elif out["outcome"] == "ROLLED_BACK":
            result.outcome = OUTCOME_ROLLED_BACK
        else:
            result.outcome = OUTCOME_EXECUTED
        result.reason = "OK"
        return result

    # ---- B2 path: online query + optional query->consume barrier (M15) ----

    def execute_b2(
        self,
        *,
        request: Mapping[str, Any],
        jti: str,
        result: TrialResult | None = None,
        barrier_after_query: Callable[[], None] | None = None,
        rollback_once: bool = False,
    ) -> TrialResult:
        result = result or TrialResult(group="B2")
        if self.b2_verifier is None:
            result.outcome = OUTCOME_REJECTED
            result.reason = "B2_VERIFIER_NOT_CONFIGURED"
            return result
        actual = self._recompute_digest(request)
        if request.get("executor_id") != self.executor_id:
            result.outcome = OUTCOME_REJECTED
            result.reason = "EXECUTOR_TARGET_MISMATCH"
            return result
        result.t_exec_attempt = self.clock.now()
        decision = self.b2_verifier.verify(
            jti=jti, action_digest=actual, executor_id=self.executor_id
        )
        # Linearization point: the moment the service returns ALLOW (§6.4).
        result.t_query = self.clock.now()
        if not decision.get("ok"):
            result.outcome = OUTCOME_REJECTED
            result.reason = REASON_B2_PREFIX + str(decision.get("reason", "DENIED"))
            return result
        # M15 hook: pause after query, revoke, then resume -- the revocation is
        # invisible to this already-allowed execution (documented boundary).
        if barrier_after_query is not None:
            barrier_after_query()
        result.t_consume = self.clock.now()
        return self._consume_and_effect(
            jti=jti, action_digest=actual, path="B2", result=result,
            rollback_once=rollback_once,
        )

    # ---- C0 / C1 paths: offline credential, no snapshot ----

    def execute_c_offline(
        self,
        *,
        group: str,
        request: Mapping[str, Any],
        credential: Mapping[str, Any],
        result: TrialResult | None = None,
        rollback_once: bool = False,
    ) -> TrialResult:
        result = result or TrialResult(group=group)
        result.t_exec_attempt = self.clock.now()
        try:
            jti, actual = self.verify_credential(
                request=request, credential=credential, now=self.clock.now()
            )
        except H1VerificationError as exc:
            result.outcome = OUTCOME_REJECTED
            result.reason = str(exc)
            return result
        result.t_consume = self.clock.now()
        return self._consume_and_effect(
            jti=jti, action_digest=actual, path=group, result=result,
            rollback_once=rollback_once,
        )

    # ---- C2 path: pre-exec refresh flow + revocation check ----

    def _c2_prepare_refresh(self, *, jti: str, result: TrialResult) -> RestoredState | None:
        """Run §5.3 pre-exec decision; return the restored trusted state.

        Returns None on fail-closed paths (S0/S2/no usable snapshot), with the
        result already marked REJECTED + reason.
        """
        if self.snapshot_state is None:
            result.outcome = OUTCOME_REJECTED
            result.reason = REASON_STATE_UNAVAILABLE
            result.snapshot_state_ok = False
            return None
        st = self.snapshot_state.state()
        if st == STATE_S2_CORRUPT:
            result.outcome = OUTCOME_REJECTED
            result.reason = REASON_STATE_UNAVAILABLE
            result.snapshot_state_ok = False
            result.snapshot_accepted = False
            return None
        restored = self.snapshot_state.restore()
        result.snapshot_state_ok = True
        result.snapshot_version_cached = restored.cached_snapshot["version"]
        result.high_water_version = restored.high_water_version
        result.snapshot_valid_until = restored.cached_snapshot["valid_until"]
        result.t_last_refresh_local = restored.last_refresh_local
        result.initialized = True
        result.bootstrap_mode = restored.bootstrap_mode

        now = self.clock.now()
        age = now - restored.last_refresh_local
        cached = restored.cached_snapshot
        refresh_due = (
            cached is None or age >= self.R or now >= cached["valid_until"]
        )
        if not refresh_due:
            result.refresh_outcome = NO_REFRESH_NEEDED
            result.refresh_attempts = 0
            return restored

        # At most ONE refresh attempt per execution (design §5.3.5).
        result.refresh_attempts = 1
        candidate: dict[str, Any] | None = None
        t0 = time.perf_counter()
        try:
            if self.snapshot_fetcher is not None:
                candidate = self.snapshot_fetcher(now)
        except Exception:
            candidate = None
        result.refresh_latency_ms = (time.perf_counter() - t0) * 1000.0

        accepted = False
        if candidate is not None:
            result.snapshot_version_candidate = (
                candidate.get("version") if isinstance(candidate, Mapping) else None
            )
            try:
                v0 = time.perf_counter()
                new_state = self.snapshot_state.accept_candidate(
                    candidate,
                    trusted_keys=self.trusted_keys,
                    trusted_issuer=self.trusted_issuer,
                    now=now,
                    trusted_channel=True,
                )
                result.snapshot_verify_ms = (time.perf_counter() - v0) * 1000.0
                result.snapshot_accepted = True
                result.refresh_outcome = REFRESH_SUCCESS
                result.snapshot_version_cached = new_state.cached_snapshot["version"]
                result.snapshot_valid_until = new_state.cached_snapshot["valid_until"]
                result.high_water_version = new_state.high_water_version
                result.t_last_refresh_local = new_state.last_refresh_local
                result.t_snapshot_obtained = now
                result.w_risk_path = "ONLINE_REFRESH_OK"
                accepted = True
            except SnapshotValidationError:
                result.snapshot_accepted = False
            except SnapshotStateError:
                result.snapshot_accepted = False

        if not accepted:
            # Refresh failed: stale-but-unexpired cache may continue; otherwise
            # fail closed. t_last_refresh_local is NOT updated (design §5.3.5).
            result.t_last_refresh_local = restored.last_refresh_local
            if cached is not None and now < cached["valid_until"]:
                result.refresh_outcome = REFRESH_FAILED_STALE_CONTINUE
                result.w_risk_path = "OFFLINE_STALE_CONTINUE"
            else:
                result.refresh_outcome = REFRESH_FAILED_FAIL_CLOSED
                result.outcome = OUTCOME_REJECTED
                result.reason = REASON_SNAPSHOT_UNAVAILABLE
                return None
        return self.snapshot_state.restore()

    def execute_c2(
        self,
        *,
        request: Mapping[str, Any],
        credential: Mapping[str, Any],
        result: TrialResult | None = None,
        rollback_once: bool = False,
    ) -> TrialResult:
        result = result or TrialResult(group="C2")
        result.t_exec_attempt = self.clock.now()
        try:
            jti, actual = self.verify_credential(
                request=request, credential=credential, now=self.clock.now()
            )
        except H1VerificationError as exc:
            result.outcome = OUTCOME_REJECTED
            result.reason = str(exc)
            return result

        restored = self._c2_prepare_refresh(jti=jti, result=result)
        if restored is None:
            return result

        # Revocation check on the ACTUALLY selected snapshot. A known revocation
        # is never bypassed by refresh failure / staleness (design §6.2 / H2-d1).
        selected = restored.cached_snapshot
        result.snapshot_version_cached = selected["version"]
        result.snapshot_valid_until = selected["valid_until"]
        if jti in selected.get("revoked_jtis", []):
            result.outcome = OUTCOME_REJECTED
            result.reason = REASON_REVOKED_BY_SNAPSHOT
            result.t_first_reject = self.clock.now()
            return result

        result.t_consume = self.clock.now()
        return self._consume_and_effect(
            jti=jti, action_digest=actual, path="C2", result=result,
            rollback_once=rollback_once,
        )

    # ---- bootstrap (S0 only) ----

    def bootstrap_online(self, *, trusted_channel: bool = True) -> RestoredState:
        """BOOT-ONLINE: fetch the current snapshot via the trusted online path."""
        if self.snapshot_state is None:
            raise StateUnavailable()
        now = self.clock.now()
        candidate = None
        if self.snapshot_fetcher is not None:
            candidate = self.snapshot_fetcher(now)
        if candidate is None:
            raise StateUnavailable()
        return self.snapshot_state.bootstrap(
            candidate,
            trusted_keys=self.trusted_keys,
            trusted_issuer=self.trusted_issuer,
            now=now,
            bootstrap_mode=BOOT_ONLINE,
            trusted_channel=trusted_channel,
        )

    def bootstrap_offline(self, snapshot: Mapping[str, Any]) -> RestoredState:
        """BOOT-OFFLINE: trusted deployment pre-provisioning (explicit assumption)."""
        if self.snapshot_state is None:
            raise StateUnavailable()
        return self.snapshot_state.bootstrap(
            snapshot,
            trusted_keys=self.trusted_keys,
            trusted_issuer=self.trusted_issuer,
            now=self.clock.now(),
            bootstrap_mode=BOOT_OFFLINE,
            trusted_channel=True,
        )

    def bootstrap_from_untrusted(self, snapshot: Mapping[str, Any]) -> None:
        """A Planner/request-channel candidate must be rejected at bootstrap."""
        if self.snapshot_state is None:
            raise StateUnavailable()
        self.snapshot_state.bootstrap(
            snapshot,
            trusted_keys=self.trusted_keys,
            trusted_issuer=self.trusted_issuer,
            now=self.clock.now(),
            bootstrap_mode=BOOT_ONLINE,
            trusted_channel=False,
        )


# ---------------------------------------------------------------------------
# Online snapshot distribution channel (trusted path for BOOT-ONLINE & refresh).
#
# Uses the same real TCP+TLS + server-certificate-fingerprint-pinning mechanism
# as B2 (reusing H1's _make_self_signed_cert). The Authorization Service signs
# the current cumulative revocation snapshot with its Ed25519 key.
# ---------------------------------------------------------------------------


class SnapshotAuthority:
    """Service-side builder of signed, cumulative revocation snapshots."""

    def __init__(
        self,
        service: AuthorizationService,
        *,
        validity_seconds: float = 120.0,
    ) -> None:
        self.service = service
        self.validity_seconds = float(validity_seconds)
        self._revoked: set[str] = set()
        self._version = 0

    def revoke(self, jti: str) -> None:
        self.service.revoke(jti)
        self._revoked.add(jti)

    def revoked_count(self) -> int:
        return len(self._revoked)

    def current_snapshot(self, generated_at: float) -> dict[str, Any]:
        self._version += 1
        return build_snapshot(
            version=self._version,
            issuer=self.service.issuer,
            key_id=self.service.key_id,
            generated_at=generated_at,
            valid_from=generated_at,
            valid_until=generated_at + self.validity_seconds,
            revoked_jtis=sorted(self._revoked),
            signing_key=self.service.signing_key,
        )


class SnapshotTLSServer:
    """Real TCP+TLS server exposing the current signed revocation snapshot."""

    def __init__(self, authority: SnapshotAuthority) -> None:
        self.authority = authority
        self._ctx, self.cert_fingerprint = _make_self_signed_cert()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.host = "127.0.0.1"
        self.port = 0

    def start(self) -> tuple[str, int, str]:
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, 0))
        self._listener.listen(16)
        self.host, self.port = self._listener.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self.host, self.port, self.cert_fingerprint

    def _serve(self) -> None:
        assert self._listener is not None
        self._listener.settimeout(0.3)
        while not self._stop.is_set():
            try:
                raw, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket) -> None:
        try:
            with self._ctx.wrap_socket(raw, server_side=True) as conn:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                line = buf.split(b"\n", 1)[0]
                req = __import__("json").loads(line.decode("utf-8"))
                gen_at = float(req["generated_at"])
                snap = self.authority.current_snapshot(gen_at)
                conn.sendall(canonical_json_bytes({"snapshot": snap}) + b"\n")
        except Exception as exc:  # malformed request -> deny, never crash
            try:
                raw.sendall(canonical_json_bytes({"error": type(exc).__name__}) + b"\n")
            except Exception:
                pass
        finally:
            try:
                raw.close()
            except Exception:
                pass

    def shutdown(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)


class SnapshotOnlineFetcher:
    """Executor-side trusted fetcher: TLS + pinned server cert; unreachable -> None."""

    def __init__(self, *, host: str, port: int, pinned_fingerprint: str) -> None:
        self.host = host
        self.port = port
        self.pinned_fingerprint = pinned_fingerprint
        self.available = True  # test hook to simulate service unreachable

    def fetch(self, generated_at: float, timeout: float = 3.0) -> dict[str, Any] | None:
        if not self.available:
            return None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # trust anchor = pinned fingerprint
            with socket.create_connection((self.host, self.port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host) as conn:
                    der = conn.getpeercert(binary_form=True)
                    if der is None:
                        return None
                    import hashlib

                    fp = hashlib.sha256(der).hexdigest()
                    if fp != self.pinned_fingerprint:
                        return None
                    conn.sendall(
                        canonical_json_bytes({"generated_at": generated_at}) + b"\n"
                    )
                    data = b""
                    while b"\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            return None
                        data += chunk
                    resp = __import__("json").loads(
                        data.split(b"\n", 1)[0].decode("utf-8")
                    )
                    snap = resp.get("snapshot")
                    return snap if isinstance(snap, dict) else None
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Harness: one independent instance per scenario (own service/TLS/sink/state).
# ---------------------------------------------------------------------------

BASE_REQUEST: dict[str, Any] = {
    "executor_id": "executor-main",
    "server_uri": "https://mcp.example.test/mcp",
    "tool_name": "send_email",
    "schema_hash": "sha256:" + "1" * 64,
    "arguments": {"to": "alice@example.test", "subject": "hi", "body": "hello"},
}


def fresh_request(**overrides: Any) -> dict[str, Any]:
    req = dict(BASE_REQUEST)
    req["arguments"] = dict(BASE_REQUEST["arguments"])
    req.update(overrides)
    return req


@dataclass
class H2Harness:
    """Own authorization service, TLS servers, Sink, and snapshot state."""

    workdir: Path
    executor_id: str = "executor-main"
    clock: LogicalClock = field(default_factory=LogicalClock)
    service: AuthorizationService = field(default_factory=AuthorizationService)
    authority: SnapshotAuthority | None = None
    b2_tls: AuthServiceTLSServer | None = None
    snap_tls: SnapshotTLSServer | None = None
    sink: ControlledSink | None = None
    snapshot_state: SnapshotStateStore | None = None
    executor: H2Executor | None = None
    b2_verifier: B2OnlineVerifier | None = None
    snapshot_fetcher: SnapshotOnlineFetcher | None = None
    trusted_keys: dict[str, Ed25519PublicKey] = field(default_factory=dict)
    validity_seconds: float = 120.0
    refresh_interval: float = 30.0

    def __post_init__(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        # Protocol §3.6: all four groups share the SAME injected clock. H1's
        # AuthorizationService exposes a `_clock` seam; wire it to the injected
        # logical clock so B2's TLS query_online (which calls _clock internally)
        # sees the same `now` as the C credential verifier. H1 source unchanged.
        self.service._clock = self.clock.now
        self.authority = SnapshotAuthority(
            self.service, validity_seconds=self.validity_seconds
        )
        self.b2_tls = AuthServiceTLSServer(self.service)
        host, port, fp = self.b2_tls.start()
        self.b2_verifier = B2OnlineVerifier(
            host=host, port=port, pinned_fingerprint=fp
        )
        self.snap_tls = SnapshotTLSServer(self.authority)
        sh, sp, sfp = self.snap_tls.start()
        self.snapshot_fetcher = SnapshotOnlineFetcher(
            host=sh, port=sp, pinned_fingerprint=sfp
        )
        self.sink = ControlledSink(
            self.workdir / f"sink-{uuid.uuid4().hex}.sqlite3"
        )
        self.snapshot_state = SnapshotStateStore(
            self.workdir / f"state-{uuid.uuid4().hex}.sqlite3"
        )
        pub = Ed25519PublicKey.from_public_bytes(self.service.public_key_bytes())
        self.trusted_keys = {self.service.key_id: pub}
        self.executor = H2Executor(
            executor_id=self.executor_id,
            sink=self.sink,
            clock=self.clock,
            trusted_keys=self.trusted_keys,
            trusted_issuer=self.service.issuer,
            trusted_audience=self.service.audience,
            b2_verifier=self.b2_verifier,
            snapshot_state=self.snapshot_state,
            refresh_interval=self.refresh_interval,
            snapshot_fetcher=self.snapshot_fetcher.fetch,
        )

    # ---- authorization helpers ----

    def authorize(
        self,
        *,
        request: dict[str, Any] | None = None,
        ttl: float = 300.0,
        now: float | None = None,
    ) -> tuple[str, dict[str, Any]]:
        request = request or fresh_request()
        n = self.clock.now() if now is None else now
        jti = f"jti-{uuid.uuid4().hex}"
        self.service.confirm(request=request, jti=jti, ttl_seconds=ttl, now=n)
        cred = self.service.issue_credential(jti, now=n)
        return jti, cred

    def revoke(self, jti: str, *, now: float | None = None) -> float:
        self.authority.revoke(jti)  # also marks the snapshot authority's set
        return self.clock.now() if now is None else now

    def auth_ref(self, jti: str) -> dict[str, Any]:
        return {"jti": jti, "action_digest": compute_action_digest(BASE_REQUEST)}

    def effects_added_since(self, before: int) -> int:
        return self.sink.effect_count() - before

    def close(self) -> None:
        if self.b2_tls is not None:
            self.b2_tls.shutdown()
        if self.snap_tls is not None:
            self.snap_tls.shutdown()
