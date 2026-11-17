"""E1.1 cross-language canonical encoding (Python side).

Scope is deliberately narrow: this module fixes byte-level encodings that
Python and Rust must share -- canonical JSON, SHA-256 digest entry points,
Pallas Fp hex, uint32 <-> Fp conversion, proof Base64, and digest format
validation. It is an *encoding layer only*: it performs no proof verification,
computes no Poseidon commitment, and must never be used as a substitute for the
frozen D11.3-B.1 Halo2 circuit or the D10 authorization chain.

Canonical JSON rules are REUSED from ``online_budget.canonical`` (same
``json.dumps`` parameters); this module adds the E1.1 cross-language type
restrictions (integer range, no floats, lowercase-only field hex).
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from .canonical import canonical_json_bytes as _canonical_json_bytes
from .canonical import is_sha256 as _is_sha256

# Cross-language integer domain: exactly what serde_json can represent losslessly.
INT64_MIN = -(2**63)
UINT64_MAX = 2**64 - 1
MAX_UINT32 = 2**32 - 1

# Pallas base-field modulus (halo2_proofs 0.4 / pasta_curves 0.6, Fp).
PALLAS_FP_MODULUS = 0x40000000000000000000000000000000224698FC094CF91B992D30ED00000001
FIELD_BYTES = 32

_LOWER_HEX = frozenset("0123456789abcdef")


class E1EncodingError(ValueError):
    """Raised when a value violates the frozen E1.1 encoding rules."""


def _validate_json(value: Any, path: str = "$") -> None:
    """Enforce the E1 cross-language JSON type range before serialization."""
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not (INT64_MIN <= value <= UINT64_MAX):
            raise E1EncodingError(
                f"{path}: integer out of cross-language range [{INT64_MIN}, {UINT64_MAX}]"
            )
        return
    if isinstance(value, str):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise E1EncodingError(f"{path}: object keys must be strings")
            _validate_json(item, f"{path}.{key}")
        return
    # float (incl. NaN/Infinity), bytes, and every other type are rejected.
    raise E1EncodingError(f"{path}: unsupported JSON type {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Canonical UTF-8 bytes; reuses the frozen ``canonical.py`` serializer."""
    _validate_json(value)
    return _canonical_json_bytes(value)


def digest_object(value: Any) -> str:
    """``sha256:`` digest of the canonical bytes of a *whole object*.

    This is the entry point for the flat D_E object (E.0 §6.1); it must NOT be
    confused with ``canonical_digest`` which adds a nested domain/payload.
    """
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def canonical_digest(domain: str, payload: Any) -> str:
    """Digest of ``{"domain": domain, "payload": payload}`` (E.0 nested form)."""
    if not isinstance(domain, str):
        raise E1EncodingError("domain must be a string")
    return digest_object({"domain": domain, "payload": payload})


def fp_to_hex(value: int) -> str:
    """Canonical Pallas Fp -> 64-char lowercase little-endian hex."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise E1EncodingError("field element must be a non-bool int")
    if not (0 <= value < PALLAS_FP_MODULUS):
        raise E1EncodingError("field element out of range [0, PallasModulus)")
    return value.to_bytes(FIELD_BYTES, "little").hex()


def fp_from_hex(value: str) -> int:
    """Strict inverse of :func:`fp_to_hex`; rejects uppercase/non-canonical."""
    if not isinstance(value, str) or len(value) != FIELD_BYTES * 2:
        raise E1EncodingError("field hex must be exactly 64 characters")
    if any(ch not in _LOWER_HEX for ch in value):
        raise E1EncodingError("field hex must be lowercase [0-9a-f]")
    decoded = int.from_bytes(bytes.fromhex(value), "little")
    if decoded >= PALLAS_FP_MODULUS:
        raise E1EncodingError("non-canonical field encoding: value >= modulus")
    return decoded


def u32_to_fp_hex(value: int) -> str:
    """E1 Q/c semantics: 1 <= uint32 <= 2^32-1, bool rejected, no truncation."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise E1EncodingError("Q/c must be a non-bool int")
    if not (1 <= value <= MAX_UINT32):
        raise E1EncodingError("Q/c must be in [1, 2^32-1]")
    return fp_to_hex(value)


def fp_hex_to_u32(value: str) -> int:
    """Strict Fp -> uint32: rejects 0 and any value above 2^32-1."""
    decoded = fp_from_hex(value)
    if not (1 <= decoded <= MAX_UINT32):
        raise E1EncodingError("field value is not a nonzero uint32")
    return decoded


def proof_b64_encode(data: bytes) -> str:
    """Standard RFC 4648 Base64 with padding; rejects empty proof bytes."""
    if not isinstance(data, (bytes, bytearray)):
        raise E1EncodingError("proof data must be bytes")
    if len(data) == 0:
        raise E1EncodingError("empty proof is not allowed")
    return base64.b64encode(bytes(data)).decode("ascii")


def proof_b64_decode(value: str) -> bytes:
    """Strict Base64 decode: canonical round-trip, padding and alphabet checked."""
    if not isinstance(value, str) or len(value) == 0:
        raise E1EncodingError("proof base64 must be a non-empty string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:  # binascii.Error / ValueError
        raise E1EncodingError("invalid base64 proof") from exc
    if len(decoded) == 0:
        raise E1EncodingError("empty proof is not allowed")
    if base64.b64encode(decoded).decode("ascii") != value:
        raise E1EncodingError("non-canonical base64 proof")
    return decoded


def is_sha256(value: Any) -> bool:
    """Reuse the frozen digest-format validator from ``canonical.py``."""
    return _is_sha256(value)


__all__ = [
    "E1EncodingError",
    "INT64_MIN",
    "UINT64_MAX",
    "MAX_UINT32",
    "PALLAS_FP_MODULUS",
    "FIELD_BYTES",
    "canonical_json_bytes",
    "digest_object",
    "canonical_digest",
    "fp_to_hex",
    "fp_from_hex",
    "u32_to_fp_hex",
    "fp_hex_to_u32",
    "proof_b64_encode",
    "proof_b64_decode",
    "is_sha256",
]
