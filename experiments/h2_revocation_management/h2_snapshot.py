"""H2 revocation snapshot: canonical form, Ed25519 signing, and candidate validation.

This module implements design docs/H2_REVOCATION_DESIGN.md §4 (snapshot format)
and §5.1/§5.2 (accept/reject rules). It is a NEW module: no H1 file is modified.

Frozen facts (do not drift):
- domain is fixed to ``h2-revocation-snapshot-v1`` (distinct from the credential
  domain ``h1-authorization-credential-v1``).
- ``signature`` covers every field EXCEPT itself, over canonical_json_bytes
  (reused verbatim from online_budget.canonical, allow_nan=False).
- public keys come ONLY from the Executor's pre-configured ``trusted_keys``;
  a key/cert supplied by a request or inside a snapshot is never trusted.
- ``revoked_jtis`` is a cumulative set, de-duplicated and lexicographically
  sorted; an incremental/delta set is forbidden (missing one delta loses a
  revocation forever).
- Rejection codes are exactly:
    SNAPSHOT_SIGNATURE_INVALID / SNAPSHOT_UNTRUSTED / SNAPSHOT_VERSION_STALE /
    SNAPSHOT_EXPIRED / SNAPSHOT_NOT_YET_VALID / SNAPSHOT_MALFORMED.
- Validation is PURE: it never mutates any cache or high-water version. The
  caller (h2_snapshot_state) is responsible for the "reject => cache unchanged"
  invariant; this module simply never writes state.

Boundaries: a validly-signed snapshot only reflects what the service wrote into
``revoked_jtis`` at ``generated_at``; it is not proof of "global immediate
revocation" or of freshness. Freshness at bootstrap comes from a trusted
channel (BOSS-ONLINE TLS pull), not from signature verification.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from online_budget.canonical import (
    b64decode,
    b64encode,
    canonical_json_bytes,
    sha256_hex,
)

SNAPSHOT_DOMAIN = "h2-revocation-snapshot-v1"

# Signed fields, in canonical form. ``signature`` is intentionally excluded.
SIGNED_FIELDS = (
    "domain",
    "version",
    "issuer",
    "key_id",
    "generated_at",
    "valid_from",
    "valid_until",
    "revoked_jtis",
)

# Frozen rejection codes (design §5.2).
REASON_SIGNATURE_INVALID = "SNAPSHOT_SIGNATURE_INVALID"
REASON_UNTRUSTED = "SNAPSHOT_UNTRUSTED"
REASON_VERSION_STALE = "SNAPSHOT_VERSION_STALE"
REASON_EXPIRED = "SNAPSHOT_EXPIRED"
REASON_NOT_YET_VALID = "SNAPSHOT_NOT_YET_VALID"
REASON_MALFORMED = "SNAPSHOT_MALFORMED"


class SnapshotValidationError(ValueError):
    """Raised when a candidate snapshot is rejected; ``code`` is a frozen code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def normalize_revoked_jtis(values: Any) -> list[str]:
    """Return de-duplicated, lexicographically sorted jti strings.

    Raises ValueError on any non-string element. This is the ONLY accepted
    canonical form for the cumulative revocation set (design §4.1/§5.1.1).
    """
    if not isinstance(values, (list, tuple)):
        raise ValueError("revoked_jtis must be a list")
    if any(not isinstance(v, str) for v in values):
        raise ValueError("revoked_jtis must contain only strings")
    return sorted(set(values))


def snapshot_payload(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Extract the signed payload (all fields except ``signature``)."""
    if not isinstance(snapshot, Mapping):
        raise ValueError("snapshot must be a mapping")
    missing = [k for k in SIGNED_FIELDS if k not in snapshot]
    if missing:
        raise ValueError(f"snapshot missing fields: {missing}")
    return {k: snapshot[k] for k in SIGNED_FIELDS}


def build_snapshot(
    *,
    version: int,
    issuer: str,
    key_id: str,
    generated_at: float,
    valid_from: float,
    valid_until: float,
    revoked_jtis: Any,
    signing_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    """Build and sign a revocation snapshot (Authorization Service side).

    ``revoked_jtis`` is normalized (de-dup + sort) before signing so the signed
    bytes have one canonical representation. Returns the full snapshot dict
    including ``signature``.
    """
    payload = {
        "domain": SNAPSHOT_DOMAIN,
        "version": version,
        "issuer": issuer,
        "key_id": key_id,
        "generated_at": generated_at,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "revoked_jtis": normalize_revoked_jtis(revoked_jtis),
    }
    # fail early on non-finite numbers / non-JSON values (allow_nan=False).
    payload_bytes = canonical_json_bytes(payload)
    signature = b64encode(signing_key.sign(payload_bytes))
    return {**payload, "signature": signature}


def snapshot_digest(snapshot: Mapping[str, Any]) -> str:
    """Digest of the whole snapshot; used for cached-state integrity checks."""
    return sha256_hex(dict(snapshot))


def snapshot_payload_bytes(snapshot: Mapping[str, Any]) -> int:
    """Byte length of the canonical signed payload (Q4 payload-size metric)."""
    return len(canonical_json_bytes(snapshot_payload(snapshot)))


def verify_snapshot_signature(
    snapshot: Mapping[str, Any], *, trusted_keys: Mapping[str, Ed25519PublicKey]
) -> None:
    """Verify Ed25519 signature using ONLY a pre-configured trusted public key.

    Raises SnapshotValidationError(REASON_UNTRUSTED) on unknown key_id and
    SnapshotValidationError(REASON_SIGNATURE_INVALID) on a bad signature.
    """
    payload = snapshot_payload(snapshot)
    key_id = payload.get("key_id")
    pub = trusted_keys.get(key_id) if isinstance(key_id, str) else None
    if pub is None:
        raise SnapshotValidationError(REASON_UNTRUSTED)
    sig = snapshot.get("signature")
    if not isinstance(sig, str):
        raise SnapshotValidationError(REASON_SIGNATURE_INVALID)
    try:
        pub.verify(b64decode(sig), canonical_json_bytes(payload))
    except (ValueError, InvalidSignature) as exc:
        raise SnapshotValidationError(REASON_SIGNATURE_INVALID) from exc


def validate_snapshot(
    snapshot: Any,
    *,
    trusted_keys: Mapping[str, Ed25519PublicKey],
    trusted_issuer: str,
    now: float,
    high_water_version: int | None = None,
    trusted_channel: bool = True,
    require_version_advance: bool = True,
) -> dict[str, Any]:
    """Validate a candidate snapshot; return its canonical payload on success.

    Args:
        trusted_keys: Executor pre-configured ``key_id -> public key`` only.
        trusted_issuer: Executor pre-configured expected issuer.
        now: injected (logical) clock used for validity-window checks.
        high_water_version: persisted HWM; when provided (and
            ``require_version_advance``) a candidate with ``version <= HWM`` is
            rejected as REASON_VERSION_STALE. ``None`` is used only at bootstrap
            where no HWM exists yet.
        trusted_channel: False means the candidate arrived over an untrusted
            channel (e.g. Planner request during bootstrap) -> REASON_UNTRUSTED
            even if the signature is valid (design §5.5 M07d).
        require_version_advance: set False only for the bootstrap exception.

    Raises:
        SnapshotValidationError with one of the six frozen codes.

    This function is pure: on any rejection the caller's cache/HWM are untouched.
    """
    # 1. structure / canonical form (SNAPSHOT_MALFORMED).
    if not isinstance(snapshot, Mapping):
        raise SnapshotValidationError(REASON_MALFORMED)
    missing = [k for k in (*SIGNED_FIELDS, "signature") if k not in snapshot]
    if missing:
        raise SnapshotValidationError(REASON_MALFORMED)
    if snapshot.get("domain") != SNAPSHOT_DOMAIN or not isinstance(
        snapshot.get("domain"), str
    ):
        # domain wrong type or wrong value: type error is malformed, wrong
        # value is untrusted. Distinguish explicitly.
        if not isinstance(snapshot.get("domain"), str):
            raise SnapshotValidationError(REASON_MALFORMED)
    version = snapshot.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise SnapshotValidationError(REASON_MALFORMED)
    for f in ("issuer", "key_id"):
        if not isinstance(snapshot.get(f), str):
            raise SnapshotValidationError(REASON_MALFORMED)
    for f in ("generated_at", "valid_from", "valid_until"):
        v = snapshot.get(f)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            raise SnapshotValidationError(REASON_MALFORMED)
    # revoked_jtis must already be the canonical form (dedup + sorted strings).
    rj = snapshot.get("revoked_jtis")
    if not isinstance(rj, list) or any(not isinstance(v, str) for v in rj):
        raise SnapshotValidationError(REASON_MALFORMED)
    if rj != sorted(set(rj)):
        raise SnapshotValidationError(REASON_MALFORMED)
    # self-consistency of time fields.
    if not (snapshot["valid_from"] <= snapshot["generated_at"] < snapshot["valid_until"]):
        raise SnapshotValidationError(REASON_MALFORMED)
    # canonical-JSON serializability (non-finite floats already filtered, but
    # keep the guard for any future field type).
    try:
        canonical_json_bytes(snapshot_payload(snapshot))
    except ValueError as exc:
        raise SnapshotValidationError(REASON_MALFORMED) from exc

    # 2/3. domain + trust anchor (SNAPSHOT_UNTRUSTED).
    if snapshot["domain"] != SNAPSHOT_DOMAIN:
        raise SnapshotValidationError(REASON_UNTRUSTED)
    if snapshot["issuer"] != trusted_issuer:
        raise SnapshotValidationError(REASON_UNTRUSTED)
    if snapshot["key_id"] not in trusted_keys:
        raise SnapshotValidationError(REASON_UNTRUSTED)
    # 4. trusted channel (bootstrap freshness source).
    if not trusted_channel:
        raise SnapshotValidationError(REASON_UNTRUSTED)

    # 5. signature (SNAPSHOT_SIGNATURE_INVALID).
    verify_snapshot_signature(snapshot, trusted_keys=trusted_keys)

    # 6. validity window relative to now.
    if now >= snapshot["valid_until"]:
        raise SnapshotValidationError(REASON_EXPIRED)
    if now < snapshot["valid_from"]:
        raise SnapshotValidationError(REASON_NOT_YET_VALID)

    # 7. version monotonicity (SNAPSHOT_VERSION_STALE).
    if require_version_advance and high_water_version is not None:
        if version <= high_water_version:
            raise SnapshotValidationError(REASON_VERSION_STALE)

    return snapshot_payload(snapshot)


def is_known_rejection(code: Any) -> bool:
    """True iff ``code`` is one of the six frozen snapshot rejection codes."""
    return code in {
        REASON_SIGNATURE_INVALID,
        REASON_UNTRUSTED,
        REASON_VERSION_STALE,
        REASON_EXPIRED,
        REASON_NOT_YET_VALID,
        REASON_MALFORMED,
    }
