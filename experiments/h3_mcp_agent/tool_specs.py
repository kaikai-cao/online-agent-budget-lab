"""Shared tool specification and validators for H3.1.

Security boundary (H3.1): the DeepSeek model is an UNTRUSTED Planner. Every
tool call it returns is validated locally here before any MCP tools/call is
issued. Both the Host (untrusted-input gate) and the MCP Server (last line of
defense) use the SAME spec, so there is a single source of truth for types,
required fields and ranges.

This is parameter validation, NOT authorization. It does NOT use H1/H2 and
does NOT claim to solve prompt injection.
"""

from __future__ import annotations

from typing import Any

# Field rules: type name -> validator. Ranges are explicit, never implicit.
TOOL_SPECS: dict[str, dict[str, Any]] = {
    "search_records": {
        "description": "Search preloaded local test records by id/title/content. Read-only, no side effect.",
        "properties": {
            "query": {"type": "string", "min_length": 1, "max_length": 200},
            "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 5},
        },
        "required": ["query"],
        "has_effect": False,
    },
    "create_record": {
        "description": "Create one test record in the local SQLite test database. Has a side effect.",
        "properties": {
            "title": {"type": "string", "min_length": 1, "max_length": 200},
            "content": {"type": "string", "min_length": 1, "max_length": 5000},
        },
        "required": ["title", "content"],
        "has_effect": True,
    },
    "update_record": {
        "description": "Update a test record's content in the local SQLite test database. Has a side effect.",
        "properties": {
            "record_id": {"type": "string", "min_length": 1, "max_length": 100},
            "content": {"type": "string", "min_length": 1, "max_length": 5000},
        },
        "required": ["record_id", "content"],
        "has_effect": True,
    },
}


class ValidationError(ValueError):
    """Raised when a tool call's arguments fail local validation."""


def validate_arguments(tool_name: str, arguments: Any) -> dict[str, Any]:
    """Validate untrusted tool arguments against the shared spec.

    - tool_name must be in the frozen spec (unknown tool rejected)
    - arguments must be a JSON object
    - required fields must be present
    - no unknown fields
    - each field's type and range must hold (bool is NOT int)

    Returns a NEW dict containing only valid fields (with defaults applied).
    Raises ValidationError with a stable reason code on any violation.
    """
    spec = TOOL_SPECS.get(tool_name)
    if spec is None:
        raise ValidationError(f"UNKNOWN_TOOL:{tool_name}")
    if not isinstance(arguments, dict):
        raise ValidationError("ARGUMENTS_NOT_OBJECT")

    props: dict[str, Any] = spec["properties"]
    required: list[str] = spec["required"]

    unknown = [k for k in arguments if k not in props]
    if unknown:
        raise ValidationError("UNKNOWN_FIELDS:" + ",".join(sorted(unknown)))

    missing = [k for k in required if k not in arguments]
    if missing:
        raise ValidationError("MISSING_FIELDS:" + ",".join(missing))

    cleaned: dict[str, Any] = {}
    for name, rule in props.items():
        if name not in arguments:
            if name in required:
                raise ValidationError("MISSING_FIELDS:" + name)
            if "default" in rule:
                cleaned[name] = rule["default"]
            continue
        value = arguments[name]
        expected = rule["type"]
        if expected == "string":
            if not isinstance(value, str):
                raise ValidationError(f"BAD_TYPE:{name}:expected_string")
            n = len(value)
            if n < rule.get("min_length", 0) or n > rule.get("max_length", 10**9):
                raise ValidationError(f"OUT_OF_RANGE:{name}:length={n}")
        elif expected == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValidationError(f"BAD_TYPE:{name}:expected_integer")
            if value < rule.get("minimum", -(10**18)) or value > rule.get("maximum", 10**18):
                raise ValidationError(f"OUT_OF_RANGE:{name}:value={value}")
        else:  # pragma: no cover - spec is frozen
            raise ValidationError(f"UNSUPPORTED_TYPE:{expected}")
        cleaned[name] = value

    return cleaned


class ToolDiscoveryError(ValueError):
    """MCP tools/list disagrees with the frozen local execution spec. Fail closed."""


def to_openai_tools() -> list[dict[str, Any]]:
    """Convert the shared spec into Chat Completions `tools` format.

    Kept as the offline/fallback converter. The real Host path uses
    `mcp_tools_to_openai()` so the model sees the Server's actual advertisement.
    """
    out: list[dict[str, Any]] = []
    for name, spec in TOOL_SPECS.items():
        out.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": spec["description"],
                    "parameters": {
                        "type": "object",
                        "properties": {
                            key: {
                                k: v
                                for k, v in rule.items()
                                if k != "default"
                            }
                            for key, rule in spec["properties"].items()
                        },
                        "required": list(spec["required"]),
                    },
                },
            }
        )
    return out


def mcp_tools_to_openai(mcp_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert MCP `tools/list` entries into Chat Completions `tools` format.

    The model sees what the MCP Server actually advertises, not a hard-coded
    local copy. `assert_tools_consistent()` MUST be called first so a discovery
    drift fails closed before any tool definition reaches the model.
    """
    out: list[dict[str, Any]] = []
    for t in mcp_tools:
        schema = t.get("input_schema") or {}
        out.append(
            {
                "type": "function",
                "function": {
                    "name": t.get("name"),
                    "description": t.get("description") or "",
                    "parameters": {
                        "type": "object",
                        "properties": dict(schema.get("properties") or {}),
                        "required": list(schema.get("required") or []),
                    },
                },
            }
        )
    return out


def assert_tools_consistent(mcp_tools: list[dict[str, Any]]) -> None:
    """Fail closed if MCP-discovered tools differ from the local execution spec.

    The discovery result is untrusted input too: the model is shown the Server's
    advertisement, but the Host STILL validates every call against the frozen
    local spec. If the two disagree on tool names, property names, required
    fields, field types or defaults, the Host refuses to proceed (the model is
    never called). Advisory JSON-schema metadata such as `title` is allowed.
    """
    discovered: dict[str, dict[str, Any]] = {}
    for t in mcp_tools:
        name = t.get("name")
        if not isinstance(name, str) or not name:
            raise ToolDiscoveryError("TOOL_NAME_INVALID")
        if name in discovered:
            raise ToolDiscoveryError("DUPLICATE_TOOL:" + name)
        discovered[name] = t

    expected = set(TOOL_SPECS)
    actual = set(discovered)
    if actual != expected:
        missing = ",".join(sorted(expected - actual))
        extra = ",".join(sorted(actual - expected))
        raise ToolDiscoveryError(f"TOOL_SET_MISMATCH:missing={missing}:extra={extra}")

    for name, entry in discovered.items():
        schema = entry.get("input_schema")
        if not isinstance(schema, dict):
            raise ToolDiscoveryError("BAD_INPUT_SCHEMA:" + name)
        props = schema.get("properties")
        if not isinstance(props, dict):
            raise ToolDiscoveryError("BAD_PROPERTIES:" + name)
        local = TOOL_SPECS[name]
        if set(props) != set(local["properties"]):
            raise ToolDiscoveryError("PROPERTY_SET_MISMATCH:" + name)
        required = schema.get("required")
        if not isinstance(required, list) or set(required) != set(local["required"]):
            raise ToolDiscoveryError("REQUIRED_MISMATCH:" + name)
        for field, rule in local["properties"].items():
            advertised = props[field]
            if not isinstance(advertised, dict) or advertised.get("type") != rule["type"]:
                raise ToolDiscoveryError("FIELD_TYPE_MISMATCH:" + name + "." + field)
            if "default" in rule and (
                type(advertised.get("default")) is not type(rule["default"])
                or advertised.get("default") != rule["default"]
            ):
                raise ToolDiscoveryError("DEFAULT_MISMATCH:" + name + "." + field)
