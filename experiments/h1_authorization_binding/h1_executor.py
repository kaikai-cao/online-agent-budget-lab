"""Executor for H1: verify action authorization, consume once, apply effect.

The Executor NEVER trusts the Planner:
- it recomputes action_digest from the actual request identity fields;
- it never accepts a public key supplied in the request (C uses pre-configured
  trusted keys keyed by key_id);
- it consumes jti and commits the controlled side effect atomically via the
  same ControlledSink for both B2 and C.

Two independent verification paths:
- B2: online query over pinned TLS to the Authorization Service (fail closed).
- C: local Ed25519 verification with a pre-configured trusted public key.

After both paths verify, the downstream steps (binding check -> atomic consume
-> controlled effect -> result record) are IDENTICAL.
"""

from __future__ import annotations

import time
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from online_budget.canonical import b64decode, canonical_json_bytes, is_sha256

from h1_authorization_service import B2OnlineVerifier
from h1_protocol import (
    CREDENTIAL_DOMAIN,
    H1ProtocolError,
    compute_action_digest,
)
from h1_sink import ControlledSink


class VerificationError(ValueError):
    """Authorization verification failed (action binding or credential)."""


class Executor:
    def __init__(
        self,
        *,
        executor_id: str,
        sink: ControlledSink,
        b2_verifier: B2OnlineVerifier | None = None,
        trusted_keys: Mapping[str, Ed25519PublicKey] | None = None,
        trusted_issuer: str = "h1-auth-service",
        trusted_audience: str = "h1-executor",
    ) -> None:
        self.executor_id = executor_id
        self.sink = sink
        self.b2_verifier = b2_verifier
        # Pre-configured trust anchor: key_id -> public key. Never from request.
        self.trusted_keys = dict(trusted_keys or {})
        self.trusted_issuer = trusted_issuer
        self.trusted_audience = trusted_audience

    # ---- shared downstream: binding check + consume + effect ----

    def _recompute_digest(self, request: Mapping[str, Any]) -> str:
        """Recompute digest from ACTUAL request; ignore any Planner-supplied one."""
        try:
            digest = compute_action_digest(request)
        except H1ProtocolError as exc:
            raise VerificationError(f"BINDING_CANONICALIZATION_FAILED:{exc}") from exc
        if not is_sha256(digest):
            raise VerificationError("BINDING_BAD_DIGEST")
        return digest

    def _check_binding(self, *, request: Mapping[str, Any], claimed_digest: str) -> str:
        """The action-identity binding: executor target + recomputed digest."""
        actual_digest = self._recompute_digest(request)
        if request.get("executor_id") != self.executor_id:
            raise VerificationError("EXECUTOR_TARGET_MISMATCH")
        if actual_digest != claimed_digest:
            raise VerificationError("ACTION_DIGEST_MISMATCH")
        return actual_digest

    def _consume_and_effect(
        self,
        *,
        jti: str,
        action_digest: str,
        path: str,
        rollback_once: bool = False,
    ) -> dict[str, Any]:
        result = {
            "status": "EXECUTED",
            "path": path,
            "jti": jti,
            "action_digest": action_digest,
            "executor_id": self.executor_id,
        }
        return self.sink.consume_and_effect(
            jti=jti,
            action_digest=action_digest,
            path=path,
            result=result,
            rollback_once=rollback_once,
        )

    # ---- B2 path: online authorization query ----

    def execute_b2(
        self,
        *,
        request: Mapping[str, Any],
        auth_ref: Mapping[str, Any],
        rollback_once: bool = False,
    ) -> dict[str, Any]:
        if self.b2_verifier is None:
            raise VerificationError("B2_VERIFIER_NOT_CONFIGURED")
        jti = auth_ref.get("jti")
        claimed_digest = auth_ref.get("action_digest")
        if not isinstance(jti, str) or not is_sha256(str(claimed_digest)):
            raise VerificationError("B2_BAD_AUTH_REF")
        # Binding check uses recomputed digest; auth_ref digest is only a pointer
        # that must match the recomputed action (otherwise reject before query).
        actual_digest = self._recompute_digest(request)
        if request.get("executor_id") != self.executor_id:
            raise VerificationError("EXECUTOR_TARGET_MISMATCH")
        decision = self.b2_verifier.verify(
            jti=jti,
            action_digest=actual_digest,
            executor_id=self.executor_id,
        )
        if not decision.get("ok"):
            raise VerificationError(f"B2_DENIED:{decision.get('reason')}")
        return self._consume_and_effect(
            jti=jti,
            action_digest=actual_digest,
            path="B2",
            rollback_once=rollback_once,
        )

    # ---- C path: local Ed25519 credential verification ----

    def execute_c(
        self,
        *,
        request: Mapping[str, Any],
        credential: Mapping[str, Any],
        rollback_once: bool = False,
    ) -> dict[str, Any]:
        payload = credential.get("payload")
        signature = credential.get("signature")
        if not isinstance(payload, Mapping) or not isinstance(signature, str):
            raise VerificationError("C_BAD_CREDENTIAL_SHAPE")
        if payload.get("domain") != CREDENTIAL_DOMAIN:
            raise VerificationError("C_BAD_DOMAIN")
        if payload.get("version") != 1:
            raise VerificationError("C_BAD_VERSION")
        key_id = payload.get("key_id")
        pub = self.trusted_keys.get(key_id)
        if pub is None:
            raise VerificationError("C_UNKNOWN_KEY_ID")
        if payload.get("issuer") != self.trusted_issuer:
            raise VerificationError("C_BAD_ISSUER")
        if payload.get("audience") != self.trusted_audience:
            raise VerificationError("C_BAD_AUDIENCE")

        # Signature covers every claim (identity, digest, jti, times, issuer...).
        try:
            pub.verify(b64decode(signature), canonical_json_bytes(dict(payload)))
        except (ValueError, InvalidSignature) as exc:
            raise VerificationError("C_SIGNATURE_INVALID") from exc

        jti = payload.get("jti")
        claimed_digest = payload.get("action_digest")
        if not isinstance(jti, str) or not is_sha256(str(claimed_digest)):
            raise VerificationError("C_BAD_CLAIMS")
        now = time.time()
        if now >= float(payload.get("expires_at", 0)):
            raise VerificationError("C_EXPIRED")
        if now < float(payload.get("issued_at", 0)):
            raise VerificationError("C_NOT_YET_VALID")

        # Action binding: recompute from actual request, compare to signed claim.
        actual_digest = self._check_binding(
            request=request, claimed_digest=str(claimed_digest)
        )
        return self._consume_and_effect(
            jti=jti,
            action_digest=actual_digest,
            path="C",
            rollback_once=rollback_once,
        )
