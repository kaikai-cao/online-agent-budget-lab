"""H3.2 frozen configuration and the ONE shared ActionRequest builder.

Both B2 and C construct the action object identically from TRUSTED inputs:
- executor_id / server_uri / schema_hash come from this fixed config;
- tool_name comes from the MCP tool the Host already validated;
- arguments come from the Host's normalized (post-validation) dict.

The model NEVER supplies executor_id, server_uri, schema_hash, action_digest,
jti, credential or public key. A Planner-supplied action_digest is dropped by
H1's ``action_identity``/``compute_action_digest`` (recomputed from identity).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from ..tool_specs import TOOL_SPECS
from .h1_bridge import ActionRequest, digest

# Fixed logical identity for the H3.2 executor and the local MCP test store.
# NOTE: this is a logical id over a pinned TLS query (B2) or a signed credential
# (C). It is NOT HTTPS and NOT mTLS.
EXECUTOR_ID = "h3-2-executor"
SERVER_URI = "mcp://h3-local-test-store"

# schema_hash = SHA-256 over the FROZEN local tool policy spec. This is the
# trusted policy artifact, not any schema the model echoes back.
SCHEMA_HASH = digest(
    {
        "tool_specs": TOOL_SPECS,
        "domain": "h3.2-local-tool-policy-v1",
    }
)


def build_action_request(
    *, tool_name: str, normalized_arguments: Mapping[str, Any]
) -> ActionRequest:
    """The single, shared ActionRequest constructor for B2 and C.

    Only the tool name (already validated) and normalized arguments (already
    checked by the Host) are action-specific. All identity fields are trusted
    local config. Never call this with raw Planner arguments.
    """
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("tool_name must be a non-empty string")
    if not isinstance(normalized_arguments, Mapping):
        raise ValueError("normalized_arguments must be a mapping")
    return ActionRequest(
        executor_id=EXECUTOR_ID,
        server_uri=SERVER_URI,
        tool_name=tool_name,
        schema_hash=SCHEMA_HASH,
        arguments=dict(normalized_arguments),
    )


def schema_hash_hex() -> str:
    """Return the bare 64-hex form of SCHEMA_HASH for readable logs."""
    return SCHEMA_HASH.removeprefix("sha256:")


def _unused_hasher():  # pragma: no cover - kept explicit about hash primitive
    return hashlib.sha256(json.dumps(TOOL_SPECS, sort_keys=True).encode())
