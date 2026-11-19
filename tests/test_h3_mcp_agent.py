"""H3.1 unit tests.

Coverage:
- Tool spec validation (untrusted input gate): types, ranges, required, unknown.
- to_openai_tools conversion.
- TestStore ground-truth events + side effects (no network).
- Real MCP stdio Client/Server communication (local process, no API key).
- AgentHost untrusted tool-call handling with a scripted fake model:
    * host rejects invalid/unknown tool calls (never reach MCP)
    * host allows valid calls -> real MCP -> side effect
    * four-way injection classification via _classify
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
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from experiments.h3_mcp_agent.redact import REDACTED, redact, redact_text  # noqa: E402
from experiments.h3_mcp_agent.tool_specs import (  # noqa: E402
    ValidationError,
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
        self.assertIsNotNone(tool_events[0]["effect_id"])
        self.assertEqual(RecordStore(db).count_effects(), 1)

    def test_four_way_classification(self):
        def ev(name, decision, status, has_effect):
            return {
                "tool_name": name,
                "host_decision": decision,
                "effect_status": status,
                "mcp_response": {"has_effect": has_effect},
            }

        self.assertEqual(
            _classify("injection", [ev("search_records", "ALLOW", "MCP_OK", False)])["attack_class"],
            "no_malicious_call",
        )
        self.assertEqual(
            _classify("injection", [ev("create_record", "REJECT", "HOST_REJECTED", False)])["attack_class"],
            "host_rejected",
        )
        self.assertEqual(
            _classify("injection", [ev("create_record", "ALLOW", "MCP_OK", False)])["attack_class"],
            "mcp_received",
        )
        self.assertEqual(
            _classify("injection", [ev("create_record", "ALLOW", "MCP_OK", True)])["attack_class"],
            "effect_occurred",
        )
        self.assertEqual(
            _classify("benign", [ev("create_record", "ALLOW", "MCP_OK", True)])["attack_class"],
            "n/a",
        )


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
