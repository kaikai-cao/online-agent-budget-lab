"""Standalone local MCP Server for H3.1 (stdio transport).

Run as an independent process:
    python -m experiments.h3_mcp_agent.server.server --db <path>

It exposes exactly three tools (search/create/update) backed by an isolated
SQLite test database. Every real tool execution is logged with a unique
effect_id in the store. No H1/H2 code, no production DB, no external API.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# Allow direct `python <this file>` execution as well as -m.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from mcp.server.mcpserver import MCPServer  # noqa: E402

from experiments.h3_mcp_agent.server.store import TestStore  # noqa: E402

mcp = MCPServer("h31-local-test-store")
_store: TestStore | None = None


def _get_store() -> TestStore:
    global _store
    if _store is None:
        db = os.environ.get("H3_MCP_DB_PATH")
        if not db:
            raise RuntimeError("H3_MCP_DB_PATH env var is required")
        _store = TestStore(db)
    return _store


def _execute_and_stamp(tool_name: str, arguments: dict[str, Any]) -> str:
    """Run the tool and add a server-side receipt.

    `server_received=True` is emitted by the MCP Server process only after the
    call reached it and `_get_store().execute()` logged a `tool_events` row.
    It is the ground-truth evidence the classifier uses to distinguish
    "MCP Server received the call" from "Host allowed but it never arrived".
    """
    out = _get_store().execute(tool_name, arguments)
    out["server_received"] = True
    return json.dumps(out, ensure_ascii=False)


@mcp.tool()
def search_records(query: str, limit: int = 5) -> str:
    """Search preloaded local test records by id, title or content. Read-only."""
    return _execute_and_stamp("search_records", {"query": query, "limit": limit})


@mcp.tool()
def create_record(title: str, content: str) -> str:
    """Create one test record in the local SQLite test database. Has a side effect."""
    return _execute_and_stamp("create_record", {"title": title, "content": content})


@mcp.tool()
def update_record(record_id: str, content: str) -> str:
    """Update a test record's content in the local SQLite database. Has a side effect."""
    return _execute_and_stamp("update_record", {"record_id": record_id, "content": content})


def main() -> None:
    global _store
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True, help="Path to isolated test SQLite db")
    args = parser.parse_args()
    _store = TestStore(args.db)
    mcp.run("stdio")


if __name__ == "__main__":
    main()
