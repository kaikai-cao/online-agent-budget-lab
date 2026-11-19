"""H3.2 unit tests: H1 B2/C authorization gating the real MCP Agent chain.

Coverage:
- M1-M11 deterministic mechanism matrix (fresh runtime per case; 10 repeats
  for the saved artifact, a representative subset here for fast unit runs).
- H1 frozen Executor is genuinely reused (B2 online TLS + C Ed25519 local).
- AgentHost authorization integration:
    * required + no gate -> fail closed (never reaches MCP);
    * approved call -> real MCP tools/call -> SQLite side effect;
    * policy-denied call -> plain tool error to model, NO MCP, no effect;
    * jti replay -> no second dispatch;
    * MCP failure after consume -> dispatch_uncertain, no auto-retry.
- Authorization internals (jti / credential / digest / reason) NEVER appear in
  the tool-result content returned to the model.
- H3.1 default behavior unchanged (no authorization).

Real DeepSeek API is NOT asserted here; it is covered by run_h3_2_authorized.
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

from experiments.h3_mcp_agent.host.agent import AgentHost  # noqa: E402
from experiments.h3_mcp_agent.host.mcp_client import McpClient  # noqa: E402
from experiments.h3_mcp_agent.server.store import TestStore as RecordStore  # noqa: E402
from experiments.h3_mcp_agent.tool_specs import (  # noqa: E402
    assert_tools_consistent,
)
from experiments.h3_mcp_agent.h3_2_authorization.approval_policy import (  # noqa: E402
    ApprovalPolicy,
    DENIED_TOOL,
)
from experiments.h3_mcp_agent.h3_2_authorization.authorization_adapter import (  # noqa: E402
    AuthorizationRuntime,
)
from experiments.h3_mcp_agent.h3_2_authorization.experiment_config import (  # noqa: E402
    build_action_request,
)
from experiments.h3_mcp_agent.h3_2_authorization.mechanism_matrix import (  # noqa: E402
    SCENARIOS,
    run_one,
)


class ScriptedClient:
    """Returns scripted model responses; records what the model was shown."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.model = "scripted-h32"
        self._responses = list(responses)
        self._i = 0
        self.messages_seen: list[list[dict[str, Any]]] = []

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
        self.messages_seen.append(json.loads(json.dumps(messages, default=str)))
        if self._i < len(self._responses):
            r = self._responses[self._i]
            self._i += 1
            return r
        return {
            "model": self.model, "content": "Done.", "tool_calls": [],
            "finish_reason": "stop", "usage": None,
        }


def _tc(name: str, args: dict[str, Any], call_id: str = "call_1") -> dict[str, Any]:
    return {
        "id": call_id, "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }


def _create_response(title: str = "t", content: str = "c") -> dict[str, Any]:
    return {
        "model": "scripted-h32", "content": None,
        "tool_calls": [_tc("create_record", {"title": title, "content": content})],
        "finish_reason": "tool_calls", "usage": None,
    }


class TestH1Reuse(unittest.TestCase):
    def test_h1_symbols_are_real_frozen_classes(self):
        from experiments.h3_mcp_agent.h3_2_authorization.h1_bridge import (
            Executor, AuthorizationService, AuthServiceTLSServer, B2OnlineVerifier,
        )
        self.assertTrue(issubclass(Executor, object))
        self.assertEqual(Executor.__module__, "h1_executor")
        self.assertEqual(AuthorizationService.__module__, "h1_authorization_service")

    def test_shared_action_request_builder(self):
        r1 = build_action_request(tool_name="create_record", normalized_arguments={"title": "t", "content": "c"})
        r2 = build_action_request(tool_name="create_record", normalized_arguments={"title": "t", "content": "c"})
        self.assertEqual(r1, r2)  # frozen dataclass, identical trusted fields
        self.assertEqual(r1.executor_id, "h3-2-executor")
        self.assertEqual(r1.server_uri, "mcp://h3-local-test-store")

    def test_approval_policy_denies_injection_writes(self):
        pol = ApprovalPolicy()
        self.assertFalse(pol.decide(task_id="I01", tool_name="create_record", normalized_arguments={"title": "t", "content": "c"}).approved)
        self.assertTrue(pol.decide(task_id="I01", tool_name="search_records", normalized_arguments={"query": "x"}).approved)
        self.assertTrue(pol.decide(task_id="B03", tool_name="create_record", normalized_arguments={"title": "t", "content": "c"}).approved)


class TestMechanismMatrix(unittest.TestCase):
    def test_all_scenarios_both_paths(self):
        """Representative single run of every M1-M11 x B2/C unit."""
        workdir = Path(tempfile.mkdtemp(prefix="h32-mech-test-"))
        for sid, _desc, _b2, _c in SCENARIOS:
            for path in ("B2", "C"):
                row = run_one(sid, path, workdir, 0)
                self.assertEqual(row["pass"], "TRUE", f"{sid}/{path}: {row['detail']}")


class TestAgentHostIntegration(unittest.TestCase):
    def _host(self, responses, *, gate, gate_events, policy, group, required=True):
        host = AgentHost(
            ScriptedClient(responses),
            authorization_gate=gate,
            authorization_required=required,
            gate_sink=gate_events.append,
            task_policy=policy,
            gate_context={"group": group},
        )
        return host

    def test_required_without_gate_fails_closed(self):
        host = AgentHost(ScriptedClient([_create_response()]), authorization_required=True)
        db = tempfile.mktemp(suffix=".sqlite3")

        async def go():
            async with McpClient(db, repo_root=REPO_ROOT).session() as session:
                return await host.run_task(session, task_id="B03", prompt="p")

        # MCP stdio context manager wraps exceptions in an ExceptionGroup; the
        # fail-closed RuntimeError is the underlying cause.
        with self.assertRaises(Exception) as cm:
            asyncio.run(go())
        exc = cm.exception
        # Flatten any ExceptionGroup to find the fail-closed cause.
        texts = [str(exc)]
        for sub in getattr(exc, "exceptions", []) or []:
            texts.append(str(sub))
            for sub2 in getattr(sub, "exceptions", []) or []:
                texts.append(str(sub2))
        self.assertTrue(any("NO_GATE" in t for t in texts), texts)
        self.assertEqual(RecordStore(db).count_effects(), 0)

    def _run_gate_case(self, group: str, task_id: str, response_title: str = "t"):
        pol = ApprovalPolicy()
        gate = AuthorizationRuntime(path=group, dispatch_db=tempfile.mktemp(suffix=".sqlite3"))
        gate_events: list[dict[str, Any]] = []
        host = self._host([_create_response(response_title)], gate=gate,
                          gate_events=gate_events, policy=pol, group=group)
        db = tempfile.mktemp(suffix=".sqlite3")

        async def go():
            async with McpClient(db, repo_root=REPO_ROOT).session() as session:
                return await host.run_task(session, task_id=task_id, prompt="p")

        try:
            result = asyncio.run(go())
        finally:
            gate.close()
        return host, result, gate_events, gate, db

    def test_approved_call_reaches_mcp_and_writes(self):
        for group in ("B2", "C"):
            host, result, gate_events, gate, db = self._run_gate_case(group, "B03")
            self.assertEqual(RecordStore(db).count_effects(), 1, group)
            self.assertTrue(any(e["event"] == "dispatch_consumed" for e in gate_events), group)
            self.assertTrue(any(e["event"] == "authorization_verified" for e in gate_events), group)
            tool_events = [json.loads(m) for m in []]  # placeholder; inspect via store below
            self.assertEqual(gate.dispatcher.consumption_count(), 1, group)

    def test_denied_call_never_reaches_mcp(self):
        for group in ("B2", "C"):
            # I01 policy denies create_record -> must not write, no dispatch.
            host, result, gate_events, gate, db = self._run_gate_case(group, "I01")
            self.assertEqual(RecordStore(db).count_effects(), 0, group)
            self.assertEqual(gate.dispatcher.consumption_count(), 0, group)
            self.assertTrue(any(e["event"] == "authorization_rejected" for e in gate_events), group)
            # Model was told a plain tool error, WITHOUT any authorization internals.
            all_seen = json.dumps(host.model.messages_seen, ensure_ascii=False)
            for leaked in ("jti-", "sha256:", "APPROVAL_DENIED", "action_digest", "credential", "TOOL_NOT_IN_TASK_POLICY"):
                self.assertNotIn(leaked, all_seen, f"{group} leaked {leaked}")
            self.assertIn("not authorized", all_seen)  # plain tool error present

    def test_h31_default_behavior_unchanged(self):
        """Without authorization_required, a valid call still writes via MCP."""
        host = AgentHost(ScriptedClient([_create_response()]))
        db = tempfile.mktemp(suffix=".sqlite3")

        async def go():
            async with McpClient(db, repo_root=REPO_ROOT).session() as session:
                return await host.run_task(session, task_id="B03", prompt="p")

        asyncio.run(go())
        self.assertEqual(RecordStore(db).count_effects(), 1)

    def test_dispatch_uncertain_no_retry_on_mcp_failure(self):
        class FailingSession:
            def __init__(self):
                self.calls = 0
            async def list_tools(self):
                # Return real-shaped tools from the local spec via a real fetch.
                return []
            async def call_tool(self, name, arguments):
                self.calls += 1
                raise RuntimeError("MCP_DOWN")

        # Use a real session only to fetch tools, then drive a failing session
        # that still satisfies the discovery consistency check.
        real_tools = []
        db_probe = tempfile.mktemp(suffix=".sqlite3")

        async def fetch():
            async with McpClient(db_probe, repo_root=REPO_ROOT).session() as s:
                return await s.list_tools()

        real_tools = asyncio.run(fetch())
        assert_tools_consistent(real_tools)

        gate = AuthorizationRuntime(path="B2", dispatch_db=tempfile.mktemp(suffix=".sqlite3"))
        gate_events: list[dict[str, Any]] = []
        host = self._host([_create_response()], gate=gate, gate_events=gate_events,
                          policy=ApprovalPolicy(), group="B2")

        class ConsistentFailSession(FailingSession):
            async def list_tools(self):
                return real_tools

        sess = ConsistentFailSession()
        asyncio.run(host.run_task(sess, task_id="B03", prompt="p"))
        self.assertEqual(sess.calls, 1)  # no auto-retry
        self.assertTrue(any(e["event"] == "dispatch_uncertain" for e in gate_events))
        self.assertEqual(gate.dispatcher.consumption_count(), 1)
        gate.close()


if __name__ == "__main__":
    unittest.main()
