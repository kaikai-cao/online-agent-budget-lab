"""Authorization Service for H1.

Two verification paths are served from the SAME trusted user-confirmation flow:

- B2 (online): the Authorization Service keeps authorization records and answers
  online queries over a real trusted TCP+TLS JSON channel. The Executor pins the
  service SERVER certificate fingerprint. B2 carries NO application-layer signed
  credential; it在线 trusts the service's current authorization state. The TCP+TLS
  channel (server-certificate fingerprint pinning, NOT HTTPS and NOT mTLS) is
  transport protection and is NOT an application-level action credential.
  When the service is unreachable, B2 fails closed.

- C (local): the Authorization Service signs an Ed25519 credential over the full
  authorization object. The Executor verifies locally with a PRE-CONFIGURED
  trusted public key (never a key supplied in the request).

Both paths can revoke and expire authorizations. The observable difference:
C can verify while the service is unreachable, but cannot learn a revocation
that happens after signing until the credential expires (architecture tradeoff).
"""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from online_budget.canonical import (
    b64encode,
    canonical_json_bytes,
    private_key_bytes,
)

from h1_protocol import (
    AuthorizationObject,
    build_authorization_object,
    credential_payload,
)

DEFAULT_ISSUER = "h1-auth-service"
DEFAULT_AUDIENCE = "h1-executor"
DEFAULT_KEY_ID = "h1-key-1"

STATE_ACTIVE = "ACTIVE"
STATE_REVOKED = "REVOKED"


class CredentialIssuanceError(ValueError):
    """Authorization Service refused to sign a credential for an authorization.

    This is an *issuance-time* refusal only. It does not change the verification
    semantics of a credential that was already signed: a credential signed while
    ACTIVE and unexpired remains locally verifiable offline, and a later
    revocation is still not visible to that offline credential (H1 architecture
    tradeoff). The `reason` attribute is stable for tests:
    UNKNOWN_JTI / REVOKED / EXPIRED.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"CREDENTIAL_ISSUANCE_REFUSED:{reason}")


@dataclass
class _Record:
    auth: AuthorizationObject
    state: str = STATE_ACTIVE


class AuthorizationService:
    """Trusted authorization side: user confirmation, records, signing, revoke."""

    def __init__(
        self,
        *,
        signing_key: Ed25519PrivateKey | None = None,
        issuer: str = DEFAULT_ISSUER,
        audience: str = DEFAULT_AUDIENCE,
        key_id: str = DEFAULT_KEY_ID,
    ) -> None:
        self.signing_key = signing_key or Ed25519PrivateKey.generate()
        self.issuer = issuer
        self.audience = audience
        self.key_id = key_id
        self._records: dict[str, _Record] = {}
        self._clock = time.time

    def public_key_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        pub = self.signing_key.public_key()
        return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def confirm(
        self,
        *,
        request: Any,
        jti: str,
        ttl_seconds: float,
        now: float | None = None,
    ) -> AuthorizationObject:
        """Trusted user-confirmation entry point (test harness stands in for UI)."""
        issued_at = self._clock() if now is None else now
        auth = build_authorization_object(
            request=request,
            jti=jti,
            issued_at=issued_at,
            expires_at=issued_at + ttl_seconds,
        )
        self._records[jti] = _Record(auth=auth)
        return auth

    def revoke(self, jti: str) -> None:
        rec = self._records.get(jti)
        if rec is not None:
            rec.state = STATE_REVOKED

    def record_state(self, jti: str) -> str | None:
        rec = self._records.get(jti)
        return rec.state if rec else None

    # ---- B2 online query (called by the TLS server) ----

    def query_online(
        self,
        *,
        jti: str,
        action_digest: str,
        executor_id: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Answer whether the given action is *currently* authorized.

        Checks existence, revocation, expiry, action-digest match and executor
        match. Uses current service state (so revocation is visible immediately).
        """
        now = self._clock() if now is None else now
        rec = self._records.get(jti)
        if rec is None:
            return {"decision": "DENY", "reason": "UNKNOWN_JTI"}
        if rec.state == STATE_REVOKED:
            return {"decision": "DENY", "reason": "REVOKED"}
        if now >= rec.auth.expires_at:
            return {"decision": "DENY", "reason": "EXPIRED"}
        if action_digest != rec.auth.action_digest:
            return {"decision": "DENY", "reason": "ACTION_DIGEST_MISMATCH"}
        if executor_id != rec.auth.executor_id:
            return {"decision": "DENY", "reason": "EXECUTOR_MISMATCH"}
        return {"decision": "ALLOW", "reason": "ONLINE_AUTHORIZED"}

    # ---- C local credential ----

    def issue_credential(self, jti: str, *, now: float | None = None) -> dict[str, Any]:
        """Sign the full authorization object into an Ed25519 credential.

        Issuance-time guard: only an existing, ACTIVE, not-yet-expired record may
        be signed. A record revoked or expired *before* issuance is refused with
        an explicit CredentialIssuanceError. This does NOT alter the semantics
        of a credential that was already signed while valid: signing it early and
        revoking afterwards still leaves the offline C verifier unable to see the
        revocation (the H1 availability/freshness tradeoff is preserved).
        """
        rec = self._records.get(jti)
        if rec is None:
            raise CredentialIssuanceError("UNKNOWN_JTI")
        if rec.state == STATE_REVOKED:
            raise CredentialIssuanceError("REVOKED")
        now = self._clock() if now is None else now
        if now >= rec.auth.expires_at:
            raise CredentialIssuanceError("EXPIRED")
        payload = credential_payload(rec.auth.as_dict())
        payload["issuer"] = self.issuer
        payload["audience"] = self.audience
        payload["key_id"] = self.key_id
        signature = b64encode(self.signing_key.sign(canonical_json_bytes(payload)))
        return {"payload": payload, "signature": signature}


# ---------------------------------------------------------------------------
# Real TLS transport for B2 (certificate pinning as the trust anchor).
# ---------------------------------------------------------------------------


def _make_self_signed_cert() -> tuple[ssl.SSLContext, str]:
    """Create an in-memory self-signed cert for 127.0.0.1; return (ctx, fp)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "h1-auth-service.test")]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(cert_der).hexdigest()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Windows CPython's load_cert_chain requires real file paths (not bytes).
    import tempfile

    tmpdir = tempfile.mkdtemp(prefix="h1-tls-")
    cert_path = __import__("os").path.join(tmpdir, "cert.pem")
    key_path = __import__("os").path.join(tmpdir, "key.pem")
    with open(cert_path, "wb") as cf:
        cf.write(cert_pem)
    with open(key_path, "wb") as kf:
        kf.write(key_pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    return ctx, fingerprint


class AuthServiceTLSServer:
    """Real TCP+TLS server exposing the B2 online query (JSON-lines per conn)."""

    def __init__(self, service: AuthorizationService) -> None:
        self.service = service
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
                req = json.loads(line.decode("utf-8"))
                resp = self.service.query_online(
                    jti=req["jti"],
                    action_digest=req["action_digest"],
                    executor_id=req["executor_id"],
                )
                conn.sendall(canonical_json_bytes(resp) + b"\n")
        except Exception as exc:  # a malformed/untrusted query is denied, not crashed
            try:
                raw.sendall(
                    canonical_json_bytes(
                        {"decision": "DENY", "reason": f"QUERY_ERROR:{type(exc).__name__}"}
                    )
                    + b"\n"
                )
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


class B2OnlineVerifier:
    """Executor-side B2 verifier: online TLS query with cert pinning; fail closed."""

    def __init__(self, *, host: str, port: int, pinned_fingerprint: str) -> None:
        self.host = host
        self.port = port
        self.pinned_fingerprint = pinned_fingerprint
        self.last_error: str | None = None

    def verify(
        self, *, jti: str, action_digest: str, executor_id: str, timeout: float = 3.0
    ) -> dict[str, Any]:
        """Return the service decision; any transport failure => fail closed."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # trust anchor = pinned fingerprint below
            with socket.create_connection((self.host, self.port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=self.host) as conn:
                    der = conn.getpeercert(binary_form=True)
                    if der is None:
                        raise RuntimeError("NO_PEER_CERT")
                    fp = hashlib.sha256(der).hexdigest()
                    if fp != self.pinned_fingerprint:
                        raise RuntimeError("CERT_PIN_MISMATCH")
                    req = {
                        "jti": jti,
                        "action_digest": action_digest,
                        "executor_id": executor_id,
                    }
                    conn.sendall(canonical_json_bytes(req) + b"\n")
                    data = b""
                    while b"\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            raise RuntimeError("EMPTY_RESPONSE")
                        data += chunk
                    resp = json.loads(data.split(b"\n", 1)[0].decode("utf-8"))
            self.last_error = None
            if resp.get("decision") != "ALLOW":
                return {"ok": False, "reason": resp.get("reason", "DENIED"), "path": "B2"}
            return {"ok": True, "reason": resp.get("reason", "ONLINE_AUTHORIZED"), "path": "B2"}
        except Exception as exc:
            # Fail closed: unreachable / cert mismatch / timeout all deny.
            self.last_error = f"{type(exc).__name__}:{exc}"
            return {"ok": False, "reason": "AUTH_SERVICE_UNREACHABLE", "path": "B2"}
