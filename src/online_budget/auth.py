from __future__ import annotations

from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import b64encode, canonical_json_bytes, verify_signature
from .errors import AuthenticationError


def gateway_signed_material(gateway_id: str, method: str, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "envelope_version": 1,
        "gateway_id": gateway_id,
        "method": method.upper(),
        "path": path,
        "payload": dict(payload),
    }


def sign_gateway_envelope(
    gateway_id: str,
    method: str,
    path: str,
    payload: Mapping[str, Any],
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    material = gateway_signed_material(gateway_id, method, path, payload)
    signature = private_key.sign(canonical_json_bytes(material))
    return {**material, "signature_b64": b64encode(signature)}


def verify_gateway_envelope(
    envelope: Mapping[str, Any],
    *,
    method: str,
    path: str,
    gateway_lookup,
) -> tuple[str, dict[str, Any]]:
    expected = {"envelope_version", "gateway_id", "method", "path", "payload", "signature_b64"}
    if not isinstance(envelope, Mapping) or set(envelope) != expected:
        raise AuthenticationError("malformed Gateway authentication envelope")
    gateway_id = envelope.get("gateway_id")
    if not isinstance(gateway_id, str) or not gateway_id.strip():
        raise AuthenticationError("missing gateway_id")
    if envelope.get("envelope_version") != 1 or envelope.get("method") != method.upper() or envelope.get("path") != path:
        raise AuthenticationError("Gateway signature is bound to a different API method or path")
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping):
        raise AuthenticationError("Gateway payload must be an object")
    key = gateway_lookup(gateway_id)
    if key is None:
        raise AuthenticationError("Gateway is not enrolled or has been disabled")
    material = gateway_signed_material(gateway_id, method, path, payload)
    try:
        verify_signature(key, envelope.get("signature_b64"), material)
    except ValueError as exc:
        raise AuthenticationError("Gateway request signature is invalid") from exc
    return gateway_id, dict(payload)
