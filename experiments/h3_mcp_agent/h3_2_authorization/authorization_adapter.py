"""B2/C authorization adapter over the FROZEN H1 implementation.

This adapter is the ONLY place that fuses the H1 authorization machinery with
the H3.1 MCP execution chain. Both groups share:
  - the same ApprovalPolicy (trusted approver simulation);
  - the same ActionRequest builder (experiment_config.build_action_request);
  - the same frozen H1 Executor verification + one-time jti consumption;
  - the same DispatchConsumptionStore.

The ONLY experimental difference is the verification path:
  - B2: Executor.execute_b2() -> real pinned-TLS online query; fail closed.
  - C : Executor.execute_c() -> local Ed25519 verification with pre-configured
        public key; works while the authorization service is offline.

Trust discipline:
  - jti is generated HERE (trusted), never from the model.
  - The model cannot call issue_credential/confirm/revoke or set approval flags.
  - Approval happens before signing; the signed/recorded object binds the FULL
    ActionRequest (incl. action_digest), so post-approval parameter tampering is
    rejected by the frozen Executor's recompute-and-compare.
  - On success the adapter grants a one-shot dispatch permission; the actual
    MCP tools/call is performed by the Host, outside this adapter.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

from .approval_policy import ApprovalDecision, ApprovalPolicy
from .dispatch_store import DispatchConsumptionStore
from .experiment_config import EXECUTOR_ID, SERVER_URI, build_action_request
from .h1_bridge import (
    DEFAULT_KEY_ID,
    AuthorizationService,
    AuthServiceTLSServer,
    B2OnlineVerifier,
    CredentialIssuanceError,
    Executor,
    VerificationError,
    action_identity,
    compute_action_digest,
)

PATH_B2 = "B2"
PATH_C = "C"

STATUS_ALLOW = "AUTHORIZED"
STATUS_REJECT = "AUTHORIZATION_REJECTED"
STATUS_UNCERTAIN = "DISPATCH_UNCERTAIN"


@dataclass
class AuthorizationOutcome:
    """Everything the Host/Runner needs to know about one authorization gate."""

    status: str
    path: str
    reason: str
    group: str = ""
    task_id: str = ""
    tool_name: str = ""
    jti: str | None = None
    action_digest: str | None = None
    approval: dict[str, Any] = field(default_factory=dict)
    jti_consumed: bool = False
    verification_latency_ms: float | None = None
    consumption_latency_ms: float | None = None
    dispatch_permitted: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "path": self.path,
            "reason": self.reason,
            "group": self.group,
            "task_id": self.task_id,
            "tool_name": self.tool_name,
            "jti": self.jti,
            "action_digest": self.action_digest,
            "approval": self.approval,
            "jti_consumed": self.jti_consumed,
            "verification_latency_ms": self.verification_latency_ms,
            "consumption_latency_ms": self.consumption_latency_ms,
            "dispatch_permitted": self.dispatch_permitted,
        }


class AuthorizationRuntime:
    """Holds the trusted authorization state for one group/arm of an experiment.

    One runtime owns one AuthorizationService, one set of signing keys, and (for
    B2) one real TLS server. The pre-configured trusted public key for C is
    derived from the service's signing key at construction and frozen in the
    Executor's key map -- the model never supplies it.
    """

    def __init__(
        self,
        *,
        path: str,
        dispatch_db: str | "object",
        ttl_seconds: float = 300.0,
    ) -> None:
        if path not in (PATH_B2, PATH_C):
            raise ValueError(f"unknown authorization path: {path}")
        self.path = path
        self.ttl_seconds = ttl_seconds
        self.service = AuthorizationService()
        self.dispatcher = DispatchConsumptionStore(dispatch_db)

        self._tls: AuthServiceTLSServer | None = None
        b2_verifier: B2OnlineVerifier | None = None
        if path == PATH_B2:
            self._tls = AuthServiceTLSServer(self.service)
            host, port, fingerprint = self._tls.start()
            b2_verifier = B2OnlineVerifier(
                host=host, port=port, pinned_fingerprint=fingerprint
            )
            self.tls_endpoint = {"host": host, "port": port, "fingerprint": fingerprint}
        else:
            self.tls_endpoint = None

        # Pre-configured trust anchor for C: key_id -> Ed25519 public key.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        trusted_pub = Ed25519PublicKey.from_public_bytes(self.service.public_key_bytes())
        self.executor = Executor(
            executor_id=EXECUTOR_ID,
            sink=self.dispatcher,
            b2_verifier=b2_verifier,
            trusted_keys={DEFAULT_KEY_ID: trusted_pub},
        )

    # -- lifecycle controls used by mechanism tests --

    def reset_dispatch_store(self, db_path: str | "object") -> None:
        """Bind a fresh per-task DispatchConsumptionStore.

        H1's frozen Executor holds its own ``sink`` reference, so both the
        runtime handle and the executor must be rebound together; otherwise
        jti consumption would silently land in a shared/older DB.
        """
        self.dispatcher = DispatchConsumptionStore(db_path)
        self.executor.sink = self.dispatcher

    def revoke(self, jti: str) -> None:
        self.service.revoke(jti)

    def stop_service(self) -> None:
        """Simulate the authorization service being unavailable (M8)."""
        if self._tls is not None:
            self._tls.shutdown()

    def close(self) -> None:
        if self._tls is not None:
            self._tls.shutdown()

    # -- trusted issue / confirm helper (not exposed to the model) --

    def _confirm_and_material(
        self, *, request: Mapping[str, Any], jti: str
    ) -> dict[str, Any]:
        """Trusted confirm; returns the reference material each path needs."""
        self.service.confirm(
            request=request, jti=jti, ttl_seconds=self.ttl_seconds
        )
        material: dict[str, Any] = {
            "jti": jti,
            "action_digest": compute_action_digest(request),
        }
        if self.path == PATH_C:
            material["credential"] = self.service.issue_credential(jti)
        return material

    # -- the single authorization gate called by the Host --

    def authorize(
        self,
        *,
        policy: ApprovalPolicy,
        task_id: str,
        tool_name: str,
        normalized_arguments: Mapping[str, Any],
        group: str = "",
        jti: str | None = None,
        request_override: Mapping[str, Any] | None = None,
        material_override: Mapping[str, Any] | None = None,
    ) -> AuthorizationOutcome:
        """Run approval -> confirm/sign -> H1 verify+consume.

        ``request_override`` / ``material_override`` are ONLY for deterministic
        mechanism tests (tampering scenarios). The real Agent path never sets
        them; all identity fields come from build_action_request().
        """
        base = AuthorizationOutcome(
            status=STATUS_REJECT,
            path=self.path,
            reason="",
            group=group,
            task_id=task_id,
            tool_name=tool_name,
        )

        # 1) Trusted approval decision (after Host validation/normalization).
        decision: ApprovalDecision = policy.decide(
            task_id=task_id, tool_name=tool_name, normalized_arguments=normalized_arguments
        )
        base.approval = decision.as_dict()
        if not decision.approved:
            base.reason = f"APPROVAL_DENIED:{decision.reason}"
            return base

        # 2) Build the trusted action object (B2 and C share this exactly).
        request = request_override if request_override is not None else build_action_request(
            tool_name=tool_name, normalized_arguments=normalized_arguments
        )
        base.action_digest = compute_action_digest(request)
        used_jti = jti or ("jti-h32-" + uuid.uuid4().hex)
        base.jti = used_jti

        # 3) Trusted confirm/sign. Mechanism tests may pass pre-built material.
        try:
            material = (
                material_override
                if material_override is not None
                else self._confirm_and_material(request=request, jti=used_jti)
            )
        except CredentialIssuanceError as exc:
            base.reason = f"CREDENTIAL_ISSUANCE_REFUSED:{exc.reason}"
            return base

        # 4) Frozen H1 Executor: recompute digest, verify, atomically consume.
        # H1's Executor expects a Mapping (it calls request.get(...)). The
        # canonical identity of an ActionRequest and its Mapping form are
        # identical by construction (action_identity), so the digest is stable.
        request_map = action_identity(request)
        t0 = time.perf_counter()
        try:
            if self.path == PATH_B2:
                auth_ref = {
                    "jti": material["jti"],
                    "action_digest": material["action_digest"],
                }
                out = self.executor.execute_b2(request=request_map, auth_ref=auth_ref)
            else:
                out = self.executor.execute_c(
                    request=request_map, credential=material["credential"]
                )
            verification_ms = (time.perf_counter() - t0) * 1000.0
        except VerificationError as exc:
            base.verification_latency_ms = round((time.perf_counter() - t0) * 1000.0, 4)
            base.reason = f"VERIFICATION_FAILED:{exc}"
            return base

        # Split the H1 Executor wall time into pure verification and the
        # one-time jti consumption (DB) cost. Neither includes model inference.
        consume_ms = self.dispatcher.last_consume_ms
        base.consumption_latency_ms = consume_ms
        base.verification_latency_ms = round(
            max(0.0, verification_ms - (consume_ms or 0.0)), 4
        )
        base.jti_consumed = True
        if out.get("outcome") != "EXECUTED":
            # DEDUP_HIT / ROLLED_BACK => no fresh dispatch permission.
            base.reason = f"CONSUMPTION_NOT_FRESH:{out.get('outcome')}"
            return base

        base.status = STATUS_ALLOW
        base.reason = f"H1_{self.path}_VERIFIED_AND_CONSUMED"
        base.dispatch_permitted = True
        return base
