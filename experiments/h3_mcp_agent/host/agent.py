"""Agent Host: DeepSeek (untrusted planner) <-> real MCP tools bridge.

Security model (H3.1):
- The model only PROPOSES tool calls. It never approves them.
- Every tool call is treated as untrusted input:
    1) `arguments` is JSON-parsed defensively;
    2) validated against the shared TOOL_SPECS via validate_arguments();
    3) only then converted into a real MCP tools/call.
  A rejected call is recorded and NEVER reaches the MCP Server.
- System prompt is NOT a security boundary. Even a compliant model is not
  trusted; validation is enforced in code.
- Multi-round loop is bounded by max_rounds to prevent infinite loops.

The full trajectory (raw model response, parsed args, validation decision,
mcp_request/mcp_response, effect_id) is returned for the JSONL log.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Callable, Mapping

from ..redact import redact
from ..tool_specs import (
    ValidationError,
    assert_tools_consistent,
    mcp_tools_to_openai,
    validate_arguments,
)
from .deepseek_client import SYSTEM_PROMPT, DeepSeekClient
from .mcp_client import McpSession

# Callback: (event_dict) -> None. Used to stream events to the JSONL logger.
EventSink = Callable[[dict[str, Any]], None]

# Optional trusted authorization gate (H3.2). The Adapter exposes authorize()
# returning an object with .as_dict() and .dispatch_permitted. The Host never
# imports H1 directly; it only calls this duck-typed gate.
AuthorizationGate = Any
GateSink = Callable[[dict[str, Any]], None]


def _parse_arguments(raw: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Parse a tool call's arguments string into a dict. Defensive."""
    if isinstance(raw, dict):
        return raw, None
    if not isinstance(raw, str):
        return None, "ARGUMENTS_NOT_STRING"
    if raw.strip() == "":
        return {}, None
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return None, "ARGUMENTS_JSON_INVALID"
    if not isinstance(parsed, dict):
        return None, "ARGUMENTS_NOT_OBJECT"
    return parsed, None


class AgentHost:
    def __init__(
        self,
        model_client: DeepSeekClient,
        *,
        max_rounds: int = 6,
        event_sink: EventSink | None = None,
        authorization_gate: AuthorizationGate | None = None,
        authorization_required: bool = False,
        gate_context: Mapping[str, Any] | None = None,
        gate_sink: GateSink | None = None,
        task_policy: Any | None = None,
    ) -> None:
        self.model = model_client
        self.max_rounds = max_rounds
        self.event_sink = event_sink
        # H3.2 authorization gate. H3.1 leaves all of these at defaults, so the
        # H3.1 behavior is byte-for-byte unchanged.
        self.authorization_gate = authorization_gate
        self.authorization_required = authorization_required
        self.gate_context = dict(gate_context or {})
        self.gate_sink = gate_sink
        self.task_policy = task_policy

    def _emit(self, event: dict[str, Any]) -> None:
        if self.event_sink is not None:
            self.event_sink(redact(event))

    def _emit_gate(self, event: dict[str, Any]) -> None:
        """Emit an authorization-layer event to the dedicated gate sink.

        Authorization internals (decisions, reasons, digests, latencies) are
        logged to the experiment record, but are NEVER placed in a message sent
        to the model.
        """
        if self.gate_sink is not None:
            self.gate_sink(redact(dict(event)))

    async def run_task(
        self,
        session: McpSession,
        *,
        task_id: str,
        prompt: str,
        model_tools: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        # FAIL CLOSED: an authorization-required run without a configured gate
        # must never reach MCP. H3.1 (authorization_required=False) skips this.
        if self.authorization_required and self.authorization_gate is None:
            raise RuntimeError("AUTHORIZATION_REQUIRED_BUT_NO_GATE_CONFIGURED")
        if model_tools is None:
            # Dynamic discovery: the model sees the tools the real MCP Server
            # actually advertises via tools/list, not a hard-coded local copy.
            # Any drift from the frozen local spec fails closed BEFORE the
            # model is called, so no tool definition is trusted implicitly.
            mcp_tools = await session.list_tools()
            assert_tools_consistent(mcp_tools)
            tools = mcp_tools_to_openai(mcp_tools)
            self._emit(
                {
                    "event": "tools_discovered",
                    "task_id": task_id,
                    "discovered_tools": [t["name"] for t in mcp_tools],
                    "discovery_source": "mcp_tools_list",
                    "discovery_consistent": True,
                    "timestamp": time.time(),
                }
            )
        else:
            # Explicit tools are only for offline/scripted tests; the real run
            # path never supplies them.
            tools = model_tools
            self._emit(
                {
                    "event": "tools_discovered",
                    "task_id": task_id,
                    "discovered_tools": [
                        (t.get("function") or {}).get("name") for t in model_tools
                    ],
                    "discovery_source": "caller_supplied",
                    "discovery_consistent": None,
                    "timestamp": time.time(),
                }
            )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        trace: list[dict[str, Any]] = []
        final_answer: str | None = None
        rounds = 0

        for rounds in range(1, self.max_rounds + 1):
            t0 = time.perf_counter()
            raw = self.model.chat(messages, tools)
            dt = time.perf_counter() - t0

            self._emit(
                {
                    "event": "model_response",
                    "task_id": task_id,
                    "round": rounds,
                    "model": raw.get("model"),
                    "model_response": raw,
                    "latency_s": round(dt, 6),
                    "timestamp": time.time(),
                }
            )
            trace.append({"round": rounds, "model_response": raw})

            tool_calls = raw.get("tool_calls") or []
            if not tool_calls:
                final_answer = raw.get("content") or ""
                self._emit(
                    {
                        "event": "final_answer",
                        "task_id": task_id,
                        "round": rounds,
                        "final_answer": final_answer,
                        "timestamp": time.time(),
                    }
                )
                break

            # Feed the assistant's tool_calls back as required by the API.
            messages.append(
                {
                    "role": "assistant",
                    "content": raw.get("content") or "",
                    "tool_calls": tool_calls,
                }
            )

            for tc in tool_calls:
                fn = tc.get("function", {}) or {}
                name = fn.get("name")
                raw_args = fn.get("arguments")
                call_id = tc.get("id")

                parsed, parse_err = _parse_arguments(raw_args)

                # --- UNTRUSTED INPUT GATE: validate before any MCP call ---
                validated: dict[str, Any] | None = None
                reject_reason: str | None = parse_err
                if parsed is not None:
                    try:
                        validated = validate_arguments(name, parsed)
                    except ValidationError as exc:
                        reject_reason = str(exc)

                mcp_request = None
                mcp_response = None
                effect_status: str
                auth_outcome: Any | None = None
                dispatch_permitted = not self.authorization_required

                if validated is None:
                    # Host REJECTED: never sent to MCP Server.
                    effect_status = "HOST_REJECTED"
                    content = json.dumps(
                        {"ok": False, "rejected_by": "host", "reason": reject_reason},
                        ensure_ascii=False,
                    )
                elif self.authorization_required:
                    # --- H3.2 AUTHORIZATION GATE (before any MCP call) ---
                    # The model never supplies jti/credential/approval: the
                    # trusted gate builds the ActionRequest from the validated
                    # arguments and fixed config, decides approval, verifies
                    # via frozen H1, and consumes the jti once.
                    self._emit_gate(
                        {
                            "event": "authorization_requested",
                            "task_id": task_id,
                            "round": rounds,
                            "tool_name": name,
                            "arguments": validated,
                            "timestamp": time.time(),
                        }
                    )
                    auth_outcome = self.authorization_gate.authorize(
                        policy=self.task_policy,
                        task_id=task_id,
                        tool_name=name,
                        normalized_arguments=validated,
                        **self.gate_context,
                    )
                    ad = (
                        auth_outcome.as_dict()
                        if hasattr(auth_outcome, "as_dict")
                        else dict(auth_outcome)
                    )
                    self._emit_gate({"event": "approval_decision", "task_id": task_id, "approval": ad.get("approval"), "timestamp": time.time()})
                    if ad.get("status") == "AUTHORIZED" and ad.get("jti_consumed"):
                        self._emit_gate({"event": "authorization_verified", "task_id": task_id, "path": ad.get("path"), "reason": ad.get("reason"), "verification_latency_ms": ad.get("verification_latency_ms"), "timestamp": time.time()})
                        self._emit_gate({"event": "dispatch_consumed", "task_id": task_id, "jti": ad.get("jti"), "action_digest": ad.get("action_digest"), "consumption_latency_ms": ad.get("consumption_latency_ms"), "timestamp": time.time()})
                        dispatch_permitted = True
                    else:
                        self._emit_gate({"event": "authorization_rejected", "task_id": task_id, "reason": ad.get("reason"), "path": ad.get("path"), "timestamp": time.time()})
                        dispatch_permitted = False

                    if dispatch_permitted:
                        mcp_request = {"tool_name": name, "arguments": validated}
                        try:
                            mcp_response = await session.call_tool(name, validated)
                            effect_status = "MCP_OK"
                        except Exception as exc:  # MCP transport / server error
                            effect_status = "MCP_ERROR"
                            mcp_response = {"ok": False, "error": type(exc).__name__ + ": " + str(exc)}
                            # jti already consumed; MCP outcome unknown -> no retry.
                            self._emit_gate({"event": "dispatch_uncertain", "task_id": task_id, "jti": ad.get("jti"), "reason": effect_status, "timestamp": time.time()})
                    else:
                        # Authorization denied/refused: return a PLAIN tool error
                        # to the model. NO MCP call, and NO authorization
                        # internals (reason/digest/jti/credential) are revealed.
                        # The detailed reason is only in the gate/event log.
                        effect_status = "AUTHORIZATION_REJECTED"
                        mcp_response = None
                    # The content sent to the model is a plain tool result.
                    content = json.dumps(
                        mcp_response
                        if mcp_response is not None
                        else {"ok": False, "error": "tool call not authorized"},
                        ensure_ascii=False,
                    )
                else:
                    mcp_request = {"tool_name": name, "arguments": validated}
                    try:
                        mcp_response = await session.call_tool(name, validated)
                        effect_status = "MCP_OK"
                    except Exception as exc:  # MCP transport / server error
                        effect_status = "MCP_ERROR"
                        mcp_response = {"ok": False, "error": type(exc).__name__ + ": " + str(exc)}
                    content = json.dumps(mcp_response, ensure_ascii=False)

                effect_id = None
                mcp_received = False
                if isinstance(mcp_response, dict):
                    effect_id = mcp_response.get("effect_id")
                    # Server-side receipt: stamped by the MCP Server process
                    # only after it logged the call in tool_events. It is NEVER
                    # inferred from host_decision=ALLOW (Host may allow a call
                    # that fails before reaching the Server).
                    mcp_received = mcp_response.get("server_received") is True

                event = {
                    "event": "tool_call",
                    "task_id": task_id,
                    "round": rounds,
                    "tool_name": name,
                    "tool_arguments": parsed,
                    "validated_arguments": validated,
                    "host_decision": "REJECT" if validated is None else "ALLOW",
                    "reject_reason": reject_reason,
                    "mcp_request": mcp_request,
                    "mcp_response": mcp_response,
                    "effect_id": effect_id,
                    "effect_status": effect_status,
                    "mcp_received": mcp_received,
                    "authorization_required": self.authorization_required,
                    "authorization_status": (
                        auth_outcome.as_dict().get("status") if auth_outcome is not None else None
                    ),
                    "authorization_reason": (
                        auth_outcome.as_dict().get("reason") if auth_outcome is not None else None
                    ),
                    "authorization_path": (
                        auth_outcome.as_dict().get("path") if auth_outcome is not None else None
                    ),
                    "authorization_latency_ms": (
                        auth_outcome.as_dict().get("verification_latency_ms")
                        if auth_outcome is not None
                        else None
                    ),
                    "jti_consumed": (
                        auth_outcome.as_dict().get("jti_consumed")
                        if auth_outcome is not None
                        else None
                    ),
                    "timestamp": time.time(),
                }
                self._emit(event)
                trace.append(
                    {
                        "round": rounds,
                        "tool_name": name,
                        "host_decision": event["host_decision"],
                        "effect_status": effect_status,
                        "mcp_received": mcp_received,
                        "effect_id": effect_id,
                        "authorization_status": event["authorization_status"],
                    }
                )

                # Always reply to the tool call so the conversation stays valid.
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": content,
                    }
                )

        if final_answer is None:
            final_answer = "[MAX_ROUNDS_REACHED]"
            self._emit(
                {
                    "event": "final_answer",
                    "task_id": task_id,
                    "round": self.max_rounds,
                    "final_answer": final_answer,
                    "timestamp": time.time(),
                }
            )

        return {
            "task_id": task_id,
            "prompt": prompt,
            "final_answer": final_answer,
            "rounds": rounds,
            "max_rounds": self.max_rounds,
            "trace": trace,
        }
