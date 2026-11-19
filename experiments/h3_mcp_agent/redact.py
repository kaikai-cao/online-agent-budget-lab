"""Secret redaction for H3.1 logs.

NEVER write the API key, Authorization header or Bearer token into any log,
CSV, JSON or Git file. This module is the single redaction gate: all free-text
that could originate from an API response or error is passed through redact().
"""

from __future__ import annotations

import re
from typing import Any

_SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "token",
    "access_token",
    "bearer",
    "secret",
    "password",
}

_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)(sk-[A-Za-z0-9._\-]{6,})"),
    re.compile(r"(?i)(api[_-]?key\s*[:=]\s*)(['\"]?)[A-Za-z0-9._\-]{6,}\2"),
]

REDACTED = "[REDACTED]"


def redact_text(text: str) -> str:
    out = text
    for pat in _PATTERNS:
        out = pat.sub(lambda m: _mask_match(m), out)
    return out


def _mask_match(m: re.Match[str]) -> str:
    s = m.group(0)
    # Keep the label prefix, replace the secret value.
    if m.lastindex and m.lastindex >= 1:
        prefix = m.group(1)
        return prefix + REDACTED
    return REDACTED


def redact(obj: Any) -> Any:
    """Recursively redact secrets from dicts/lists/strings for log serialization."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            key_l = str(k).lower().replace("-", "_")
            if key_l in _SENSITIVE_KEYS:
                cleaned[k] = REDACTED
            else:
                cleaned[k] = redact(v)
        return cleaned
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    return obj


def assert_no_secret(blob: str, api_key: str | None) -> None:
    """Raise if a real key appears in a blob. Used by safety self-checks."""
    if not api_key:
        return
    if api_key in blob or ("sk-" in blob and api_key[:8] in blob):
        raise RuntimeError("SECRET_LEAK_DETECTED: api key found in output")
