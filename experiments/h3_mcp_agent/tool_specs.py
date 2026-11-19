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


def to_openai_tools() -> list[dict[str, Any]]:
    """Convert the shared spec into Chat Completions `tools` format."""
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
