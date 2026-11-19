"""Real MCP Client wrapper (stdio transport) for H3.1.

This uses the official MCP SDK ClientSession over stdio. We do NOT implement a
fake MCP protocol. The Host connects to the standalone MCP Server process,
reads tools/list, and issues real tools/call requests.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER_MODULE = "experiments.h3_mcp_agent.server.server"
_REPO_ROOT = Path(__file__).resolve().parents[3]


def _parse_tool_result(result: Any) -> dict[str, Any]:
    """Turn a CallToolResult's text content into a plain dict."""
    parts = []
    for c in getattr(result, "content", []) or []:
        text = getattr(c, "text", None)
        if text is None:
            continue
        try:
            parts.append(json.loads(text))
        except (ValueError, TypeError):
            parts.append({"text": text})
    is_error = bool(getattr(result, "is_error", False))
    if len(parts) == 1:
        payload = parts[0]
    else:
        payload = {"parts": parts}
    if isinstance(payload, dict):
        payload = dict(payload)
        payload["mcp_is_error"] = is_error
    return payload


class McpClient:
    def __init__(self, db_path: str | Path, *, repo_root: Path | None = None) -> None:
        self.db_path = str(db_path)
        self.repo_root = Path(repo_root) if repo_root else _REPO_ROOT

    def _params(self) -> StdioServerParameters:
        env = dict(os.environ)
        # The MCP Server never needs the model API key; strip it from the child
        # process environment to minimize exposure.
        for _secret_key in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY"):
            env.pop(_secret_key, None)
        # Ensure the child can import the experiments package regardless of cwd.
        env["PYTHONPATH"] = str(self.repo_root) + os.pathsep + env.get("PYTHONPATH", "")
        return StdioServerParameters(
            command=sys.executable,
            args=["-m", SERVER_MODULE, "--db", self.db_path],
            env=env,
        )

    @asynccontextmanager
    async def session(self) -> AsyncIterator["McpSession"]:
        async with stdio_client(self._params()) as (read, write):
            async with ClientSession(read, write) as sess:
                await sess.initialize()
                yield McpSession(sess)


class McpSession:
    def __init__(self, sess: ClientSession) -> None:
        self._sess = sess

    async def list_tools(self) -> list[dict[str, Any]]:
        result = await self._sess.list_tools()
        out = []
        for t in result.tools:
            out.append(
                {
                    "name": t.name,
                    "description": t.description or "",
                    "input_schema": dict(t.input_schema or {}),
                }
            )
        return out

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = await self._sess.call_tool(name, arguments)
        return _parse_tool_result(result)
