from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"value is not canonical-JSON serializable: {exc}") from exc


def sha256_hex(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def digest(value: Any) -> str:
    return "sha256:" + sha256_hex(value)


def is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(ch in "0123456789abcdef" for ch in value[7:])
    )


def b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError("base64 value must be a string")
    return base64.b64decode(value, validate=True)


def public_key_bytes(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b64decode(value))


def private_key_from_b64(value: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b64decode(value))


def public_key_digest(key: Ed25519PublicKey) -> str:
    return "sha256:" + hashlib.sha256(public_key_bytes(key)).hexdigest()


def verify_signature(key: Ed25519PublicKey, signature_b64: str, payload: Any) -> None:
    try:
        key.verify(b64decode(signature_b64), canonical_json_bytes(payload))
    except (ValueError, InvalidSignature) as exc:
        raise ValueError("signature verification failed") from exc
