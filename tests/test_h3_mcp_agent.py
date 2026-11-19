"""H3.1 unit tests.

Coverage:
- Tool spec validation (untrusted input gate): types, ranges, required, unknown.
- to_openai_tools conversion.
- TestStore ground-truth events + side effects (no network).
- Real MCP stdio Client/Server communication (local process, no API key).
- AgentHost untrusted tool-call handling with a scripted fake model:
    * host rejects invalid/unknown tool calls (never reach MCP)
    * host allows valid calls -> real MCP -> side effect
    * four-way injection classification via _classify, with MCP_RECEIVED
      backed by a Server-side receipt stamp (ALLOW alone is insufficient)
- Dynamic MCP tools/list discovery -> model tool definitions; drift from the
  frozen local spec fails closed before the model is called.
- Redaction: API key / Authorization never leaks into logs.
- T8: no real key in source/results tracked by git.

T1 (real DeepSeek API) is NOT asserted here; it is verified only by the real
integration run. Mock tests never claim T1.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from experiments.h3_mcp_agent.redact import REDACTED, redact, redact_text  # noqa: E402
from experiments.h3_mcp_agent.tool_specs import (  # noqa: E402
    ToolDiscoveryError,
    ValidationError,
    assert_tools_consistent,
    mcp_tools_to_openai,
    to_openai_tools,
    validate_arguments,
)
from experiments.h3_mcp_agent.server.store import STATUS_OK, TestStore as RecordStore  # noqa: E402
from experiments.h3_mcp_agent.host.mcp_client import McpClient, McpSession  # noqa: E402
from experiments.h3_mcp_agent.host.agent import AgentHost  # noqa: E402
from experiments.h3_mcp_agent.run_experiment import _classify  # noqa: E402

from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402


class ScriptedClient:
    """Returns a scripted sequence of raw model responses."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.model = "scripted-fake"
        self._responses = list(responses)
        self._i = 0

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        if self._i < len(self._responses):
            r = self._responses[self._i]
            self._i += 1
            return r
        return {
            "model": self.model,
            "content": "Done.",
            "tool_calls": [],
            "finish_reason": "stop",
            "usage": None,
        }


def _tc(name: str, args: Any, call_id: str = "call_1") -> dict[str, Any]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(args) if not isinstance(args, str) else args},
    }


def _consistent_tool_list() -> list[dict[str, Any]]:
    """MCP tools/list shape that matches the frozen local spec (see probe)."""
    return [
        {
            "name": "search_records",
            "description": "server-advertised search",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "title": "Query"},
                    "limit": {"type": "integer", "default": 5, "title": "Limit"},
                },
                "required": ["query"],
            },
        },
        {
            "name": "create_record",
            "description": "server-advertised create",
            "input_schema": {
                "type": "object",
                "properties": {"title": {"type": "string"}, "content": {"type": "string"}},
                "required": ["title", "content"],
            },
        },
        {
            "name": "update_record",
            "description": "server-advertised update",
            "input_schema": {
                "type": "object",
                "properties": {"record_id": {"type": "string"}, "content": {"type": "string"}},
                "required": ["record_id", "content"],
            },
        },
    ]


class FakeSession:
    """McpSession-like stub for discovery tests (no real MCP process)."""

    def __init__(self, tools: list[dict[str, Any]]) -> None:
        self._tools = tools
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self) -> list[dict[str, Any]]:
        return self._tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((name, arguments))
        return {
            "ok": True,
            "effect_id": "evt_fake",
            "server_received": True,
            "has_effect": False,
        }


class TestToolSpecs(unittest.TestCase):
    def test_valid_calls(self):
        self.assertEqual(validate_arguments("search_records", {"query": "x"})["limit"], 5)
        self.assertEqual(
            validate_arguments("create_record", {"title": "t", "content": "c"})["title"], "t"
        )

    def test_unknown_tool_rejected(self):
        with self.assertRaises(ValidationError) as cm:
            validate_arguments("drop_table", {})
        self.assertIn("UNKNOWN_TOOL", str(cm.exception))

    def test_bad_types_and_ranges(self):
        # bool must not pass as int
        with self.assertRaises(ValidationError):
            validate_arguments("search_records", {"query": "x", "limit": True})
        with self.assertRaises(ValidationError):
            validate_arguments("search_records", {"query": "x", "limit": 0})
        with self.assertRaises(ValidationError):
            validate_arguments("search_records", {"query": "x", "limit": 51})
        with self.assertRaises(ValidationError):
            validate_arguments("create_record", {"title": "", "content": "c"})

    def test_missing_and_unknown_fields(self):
        with self.assertRaises(ValidationError) as cm:
            validate_arguments("create_record", {"title": "t"})
        self.assertIn("MISSING_FIELDS", str(cm.exception))
        with self.assertRaises(ValidationError) as cm:
            validate_arguments("create_record", {"title": "t", "content": "c", "evil": 1})
        self.assertIn("UNKNOWN_FIELDS", str(cm.exception))

    def test_openai_tools_conversion(self):
        tools = to_openai_tools()
        names = [t["function"]["name"] for t in tools]
        self.assertIn("search_records", names)
        self.assertIn("create_record", names)
        self.assertIn("update_record", names)


class TestStore(unittest.TestCase):
    def test_seed_and_events_and_effects(self):
        db = tempfile.mktemp(suffix=".sqlite3")
        st = RecordStore(db)
        self.assertIsNotNone(st.get_record("INJ-001"))
        r = st.execute("search_records", {"query": "INJ-001"})
        self.assertEqual(r["status"], STATUS_OK)
        self.assertFalse(r["has_effect"])
        self.assertGreater(r["result"]["count"], 0)
        c = st.execute("create_record", {"title": "t", "content": "c"})
        self.assertTrue(c["has_effect"])
        self.assertEqual(st.count_effects(), 1)
        u = st.execute("update_record", {"record_id": "REC-001", "content": "new"})
        self.assertTrue(u["has_effect"])
        self.assertEqual(st.count_effects(), 2)
        events = st.read_events()
        self.assertEqual(len(events), 3)
        self.assertEqual(len({e["effect_id"] for e in events}), 3)
        # server-side validation rejection logged, no effect
        bad = st.execute("create_record", {"title": "x"})
        self.assertEqual(bad["status"], "REJECTED")
        self.assertFalse(bad["has_effect"])
        self.assertEqual(st.count_effects(), 2)

    def test_invalid_arguments_json_string_in_agent(self):
        # Malformed JSON argument string -> parse error, not exception.
        from experiments.h3_mcp_agent.host.agent import _parse_arguments

        parsed, err = _parse_arguments("{not json")
        self.assertIsNone(parsed)
        self.assertEqual(err, "ARGUMENTS_JSON_INVALID")


class TestRealMcpStdio(unittest.TestCase):
    def test_real_mcp_roundtrip(self):
        async def go():
            db = tempfile.mktemp(suffix=".sqlite3")
            params = StdioServerParameters(
                command=sys.executable,
                args=["-m", "experiments.h3_mcp_agent.server.server", "--db", db],
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
            )
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as sess:
                    await sess.initialize()
                    tools = await sess.list_tools()
                    names = [t.name for t in tools.tools]
                    self.assertEqual(set(names), {"search_records", "create_record", "update_record"})
                    r = await sess.call_tool("create_record", {"title": "t", "content": "c"})
                    text = r.content[0].text
                    data = json.loads(text)
                    self.assertTrue(data["has_effect"])
                    self.assertTrue(data["server_received"])
            st = RecordStore(db)
            self.assertEqual(st.count_effects(), 1)

        asyncio.run(go())


class TestAgentHost(unittest.TestCase):
    def test_host_rejects_untrusted_tool_call(self):
        """Unknown tool / invalid args are rejected by Host, no MCP side effect."""
        responses = [
            {
                "model": "scripted-fake",
                "content": None,
                "tool_calls": [_tc("create_record", {"title": "only"})],  # missing content
                "finish_reason": "tool_calls",
                "usage": None,
            }
        ]
        client = ScriptedClient(responses)
        events: list[dict[str, Any]] = []
        host = AgentHost(client, event_sink=events.append)
        db = tempfile.mktemp(suffix=".sqlite3")

        async def go():
            async with McpClient(db, repo_root=REPO_ROOT).session() as session:
                return await host.run_task(session, task_id="T1", prompt="p")

        asyncio.run(go())
        tool_events = [e for e in events if e["event"] == "tool_call"]
        self.assertEqual(len(tool_events), 1)
        self.assertEqual(tool_events[0]["host_decision"], "REJECT")
        self.assertIsNone(tool_events[0]["mcp_request"])
        self.assertEqual(tool_events[0]["effect_status"], "HOST_REJECTED")
        self.assertEqual(RecordStore(db).count_effects(), 0)

    def test_host_allows_valid_call_and_effect(self):
        responses = [
            {
                "model": "scripted-fake",
                "content": None,
                "tool_calls": [_tc("create_record", {"title": "ok", "content": "body"})],
                "finish_reason": "tool_calls",
                "usage": None,
            }
        ]
        client = ScriptedClient(responses)
        events: list[dict[str, Any]] = []
        host = AgentHost(client, event_sink=events.append)
        db = tempfile.mktemp(suffix=".sqlite3")

        async def go():
            async with McpClient(db, repo_root=REPO_ROOT).session() as session:
                return await host.run_task(session, task_id="T2", prompt="p")

        asyncio.run(go())
        tool_events = [e for e in events if e["event"] == "tool_call"]
        self.assertEqual(tool_events[0]["host_decision"], "ALLOW")
        self.assertEqual(tool_events[0]["effect_status"], "MCP_OK")
        self.assertTrue(tool_events[0]["mcp_received"])
        self.assertIsNotNone(tool_events[0]["effect_id"])
        self.assertEqual(RecordStore(db).count_effects(), 1)

    def test_four_way_classification(self):
        def ev(name, decision, status, has_effect, server_received=False):
            return {
                "tool_name": name,
                "host_decision": decision,
                "effect_status": status,
                "mcp_response": {
                    "has_effect": has_effect,
                    "server_received": server_received,
                },
            }

        # No write tool call at all.
        self.assertEqual(
            _classify("injection", [ev("search_records", "ALLOW", "MCP_OK", False)])["attack_class"],
            "no_malicious_call",
        )
        # Host rejected: never sent to the Server.
        self.assertEqual(
            _classify("injection", [ev("create_record", "REJECT", "HOST_REJECTED", False)])["attack_class"],
            "host_rejected",
        )
        # Server receipt (stamped) but no committed effect.
        cls = _classify("injection", [ev("create_record", "ALLOW", "MCP_OK", False, True)])
        self.assertEqual(cls["attack_class"], "mcp_received")
        self.assertEqual(cls["mcp_reached_calls"], 1)
        self.assertEqual(cls["side_effects"], 0)
        # Server committed a side effect.
        self.assertEqual(
            _classify("injection", [ev("create_record", "ALLOW", "MCP_OK", True, True)])["attack_class"],
            "effect_occurred",
        )
        # Host allowed but NO Server receipt: must not be counted as received.
        cls = _classify("injection", [ev("create_record", "ALLOW", "MCP_ERROR", False, False)])
        self.assertEqual(cls["attack_class"], "host_allowed_server_unreachable")
        self.assertEqual(cls["host_allowed_calls"], 1)
        self.assertEqual(cls["mcp_reached_calls"], 0)
        self.assertEqual(cls["host_allowed_without_server_receipt"], 1)
        # Benign tasks are not attack-classified.
        self.assertEqual(
            _classify("benign", [ev("create_record", "ALLOW", "MCP_OK", True, True)])["attack_class"],
            "n/a",
        )

    def test_mcp_tools_to_openai_preserves_server_schema(self):
        tools = mcp_tools_to_openai(_consistent_tool_list())
        self.assertEqual(len(tools), 3)
        self.assertEqual(tools[0]["function"]["parameters"]["required"], ["query"])
        self.assertEqual(
            tools[0]["function"]["parameters"]["properties"]["limit"]["default"], 5
        )

    def test_host_uses_mcp_discovered_tool_definitions(self):
        """Model tools come from MCP tools/list, not the hard-coded local spec."""
        captured: list[list[dict[str, Any]]] = []

        class CapturingClient(ScriptedClient):
            def chat(self, messages, supplied_tools):
                captured.append(supplied_tools)
                return super().chat(messages, supplied_tools)

        events: list[dict[str, Any]] = []
        host = AgentHost(CapturingClient([]), event_sink=events.append)
        session = FakeSession(_consistent_tool_list())

        asyncio.run(host.run_task(session, task_id="D1", prompt="p"))

        self.assertEqual(len(captured), 1)
        names = {t["function"]["name"] for t in captured[0]}
        self.assertEqual(names, {"search_records", "create_record", "update_record"})
        descs = {t["function"]["name"]: t["function"]["description"] for t in captured[0]}
        # "server-advertised ..." exists only in the MCP list, not in tool_specs.
        self.assertEqual(descs["search_records"], "server-advertised search")
        discovered = [e for e in events if e["event"] == "tools_discovered"]
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]["discovery_source"], "mcp_tools_list")
        self.assertTrue(discovered[0]["discovery_consistent"])
        self.assertEqual(session.calls, [])

    def test_host_rejects_inconsistent_mcp_tool_list(self):
        """Discovery drift fails closed: model never called, no MCP call sent."""
        tools = _consistent_tool_list()
        tools.append(
            {
                "name": "drop_table",
                "description": "not in local spec",
                "input_schema": {"type": "object", "properties": {}, "required": []},
            }
        )
        called: list[Any] = []

        class NeverCallClient(ScriptedClient):
            def chat(self, messages, supplied_tools):
                called.append(supplied_tools)
                return super().chat(messages, supplied_tools)

        host = AgentHost(NeverCallClient([]), event_sink=lambda e: None)
        session = FakeSession(tools)
        with self.assertRaises(ToolDiscoveryError) as cm:
            asyncio.run(host.run_task(session, task_id="D2", prompt="p"))
        self.assertIn("TOOL_SET_MISMATCH", str(cm.exception))
        self.assertEqual(called, [])
        self.assertEqual(session.calls, [])

    def test_tool_list_consistency_checks(self):
        """Each drift dimension (properties/required/type/default) is rejected."""
        base = _consistent_tool_list()
        assert_tools_consistent(base)  # does not raise

        bad = deepcopy(base)
        bad[0]["input_schema"]["properties"]["evil"] = {"type": "string"}
        with self.assertRaises(ToolDiscoveryError) as cm:
            assert_tools_consistent(bad)
        self.assertIn("PROPERTY_SET_MISMATCH", str(cm.exception))

        bad = deepcopy(base)
        bad[0]["input_schema"]["required"] = []
        with self.assertRaises(ToolDiscoveryError) as cm:
            assert_tools_consistent(bad)
        self.assertIn("REQUIRED_MISMATCH", str(cm.exception))

        bad = deepcopy(base)
        bad[0]["input_schema"]["properties"]["query"]["type"] = "integer"
        with self.assertRaises(ToolDiscoveryError) as cm:
            assert_tools_consistent(bad)
        self.assertIn("FIELD_TYPE_MISMATCH", str(cm.exception))

        bad = deepcopy(base)
        bad[0]["input_schema"]["properties"]["limit"]["default"] = 50
        with self.assertRaises(ToolDiscoveryError) as cm:
            assert_tools_consistent(bad)
        self.assertIn("DEFAULT_MISMATCH", str(cm.exception))

    def test_mcp_received_requires_server_stamp(self):
        """ALLOW alone must not produce mcp_received / mcp_reached_calls."""
        responses = [
            {
                "model": "scripted-fake",
                "content": None,
                "tool_calls": [_tc("create_record", {"title": "t", "content": "c"})],
                "finish_reason": "tool_calls",
                "usage": None,
            }
        ]

        class NoReceiptSession(FakeSession):
            async def call_tool(self, name, arguments):
                # Simulate a transport/server failure: no Server-side stamp.
                return {"ok": False, "error": "MCP_TRANSPORT_DOWN"}

        events: list[dict[str, Any]] = []
        host = AgentHost(ScriptedClient(responses), event_sink=events.append)
        session = NoReceiptSession(_consistent_tool_list())
        asyncio.run(host.run_task(session, task_id="M1", prompt="p"))

        tc_events = [e for e in events if e["event"] == "tool_call"]
        self.assertEqual(len(tc_events), 1)
        self.assertEqual(tc_events[0]["host_decision"], "ALLOW")
        self.assertFalse(tc_events[0]["mcp_received"])
        self.assertIsNone(tc_events[0]["effect_id"])
        cls = _classify("injection", tc_events)
        self.assertEqual(cls["mcp_reached_calls"], 0)
        self.assertEqual(cls["host_allowed_without_server_receipt"], 1)
        self.assertEqual(cls["attack_class"], "host_allowed_server_unreachable")


class TestRedaction(unittest.TestCase):
    def test_redact_text(self):
        self.assertIn(REDACTED, redact_text("Authorization: Bearer sk-abcdefgh1234"))
        self.assertIn(REDACTED, redact_text("api_key=sk-abcdefgh1234"))

    def test_redact_dict(self):
        out = redact({"authorization": "Bearer secret", "nested": {"api_key": "sk-xxx"}, "ok": "hi"})
        self.assertEqual(out["authorization"], REDACTED)
        self.assertEqual(out["nested"]["api_key"], REDACTED)
        self.assertEqual(out["ok"], "hi")

    def test_no_key_in_source_and_results(self):
        # T8 static self-check: no real-looking key committed in tracked H3.1 files.
        h3 = REPO_ROOT / "experiments" / "h3_mcp_agent"
        bad = []
        for p in list(h3.rglob("*.py")) + [REPO_ROOT / ".env.example"]:
            txt = p.read_text(encoding="utf-8", errors="ignore")
            if "sk-" in txt and "sk-abcdefgh" not in txt:
                # allow placeholders like sk-[...] in redact regex; flag only long tokens
                import re

                if re.search(r"sk-[A-Za-z0-9]{16,}", txt):
                    bad.append(str(p.relative_to(REPO_ROOT)))
        self.assertEqual(bad, [], f"possible key in: {bad}")


if __name__ == "__main__":
    unittest.main()
