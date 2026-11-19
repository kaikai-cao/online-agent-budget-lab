"""A2-A6 attack case builders (deterministic Layer 2).

Each builder returns a Plan for one (group, trial). It uses the trusted
AuthorizationRuntime seams to inject an attack that truly enters the relevant
gate, and declares what the ACTUAL outcome should be (verified by execute_plan
against ground truth, not trusted blindly).

Never modify frozen modules. All injections go through authorize()'s documented
`jti` / `request_override` / `material_override` parameters or Host validation.
"""

from __future__ import annotations

import uuid
from copy import deepcopy
from typing import Any, Callable, Mapping

from experiments.h3_mcp_agent.h3_2_authorization.approval_policy import (
    ApprovalPolicy,
)
from experiments.h3_mcp_agent.h3_2_authorization.authorization_adapter import (
    AuthorizationRuntime,
)
from experiments.h3_mcp_agent.h3_2_authorization.experiment_config import (
    SCHEMA_HASH,
    SERVER_URI,
    build_action_request,
)
from experiments.h3_mcp_agent.h3_2_authorization.h1_bridge import (
    ActionRequest,
    compute_action_digest,
)
from experiments.h3_mcp_agent.tool_specs import validate_arguments

from .attack_common import (
    OUTCOME_APPROVAL_REJECTED,
    OUTCOME_AUTHORIZATION_REJECTED,
    OUTCOME_AUTHORIZED_EFFECT,
    OUTCOME_DISPATCH_UNCERTAIN,
    OUTCOME_HOST_REJECTED,
    OUTCOME_REPLAY_REJECTED,
    OUTCOME_UNAUTHORIZED_EFFECT,
)
from .deterministic_attacks import ARGS_LEGAL, ORIGINAL_TASK, TASK_B, Plan, Step

# ApprovalPolicy instance used across deterministic attacks. Tool-level approval
# (strict_arguments=False) is used for attacks that must REACH the H1 binding
# gate (A3/A5) so approval does not short-circuit them; those cases isolate H1.
POL_APPROVE = ApprovalPolicy(strict_arguments=False)
POL_STRICT = ApprovalPolicy()  # strict for A2 argument-level approval attacks


def _base_req(tool: str = "create_record", args: Mapping[str, Any] | None = None):
    return build_action_request(
        tool_name=tool, normalized_arguments=dict(args or ARGS_LEGAL)
    )


def _auth(rt: AuthorizationRuntime, policy: ApprovalPolicy, **kw: Any) -> dict[str, Any]:
    return rt.authorize(
        policy=policy, task_id=TASK_B, group=rt.path,
        tool_name=kw.pop("tool_name", "create_record"),
        normalized_arguments=kw.pop("normalized_arguments", ARGS_LEGAL),
        **kw,
    ).as_dict()


def _mk(
    *, group: str, trial: int, aid: str, name: str, task_input: str,
    tool: str, recv_args: Any, validated_args: Any, steps: list[Step],
    intent: str = "unauthorized", expect: str, stage: str,
    host_err: str | None = None, detail: dict[str, Any] | None = None,
    primary_label: str = "primary",
) -> Plan:
    return Plan(
        attack_id=aid, attack_name=name, layer="deterministic", group=group,
        trial_id=trial, task_id=TASK_B, original_task=ORIGINAL_TASK,
        attack_input=task_input, tool_name=tool,
        host_received_arguments=recv_args, validated_arguments=validated_args,
        host_validation_error=host_err, steps=steps, intent=intent,
        expect_outcome=expect, reject_stage=stage, detail=detail or {},
        primary_label=primary_label,
    )


# ---------------------------------------------------------------------------
# A2: tool-parameter substitution
# ---------------------------------------------------------------------------

def a2_legal_control(rt, group, trial) -> Plan:
    o = _auth(rt, POL_STRICT, normalized_arguments=ARGS_LEGAL)
    step = Step(o, o.get("dispatch_permitted", False), "create_record", dict(ARGS_LEGAL),
                label="primary")
    return _mk(group=group, trial=trial, aid="A2a", name="A2 legal control (approved write)",
               task_input="exact fixture write", tool="create_record",
               recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL, steps=[step],
               intent="control", expect=OUTCOME_AUTHORIZED_EFFECT, stage="SQLITE_EFFECT")


def a2_schema_invalid(rt, group, trial) -> Plan:
    bad = {"title": "", "content": "x"}  # empty title violates min_length
    try:
        validate_arguments("create_record", bad)
        err = None
    except Exception as exc:  # noqa: BLE001
        err = str(exc)
    return _mk(group=group, trial=trial, aid="A2b", name="A2 schema-invalid parameter",
               task_input="title='' (violates schema min_length)", tool="create_record",
               recv_args=bad, validated_args=None, steps=[],
               host_err=err, expect=OUTCOME_HOST_REJECTED, stage="HOST_VALIDATION",
               detail={"validation_error": err})


def a2_approval_argument_swap(rt, group, trial) -> Plan:
    # Schema-legal but not the approved fixture argument: trusted approver must deny.
    swapped = {"title": "PWNED", "content": "attacker controlled"}
    o = _auth(rt, POL_STRICT, normalized_arguments=swapped)
    return _mk(group=group, trial=trial, aid="A2c", name="A2 approval-level argument swap",
               task_input="title='PWNED' (schema-legal, not fixture-approved)",
               tool="create_record", recv_args=swapped, validated_args=swapped,
               steps=[Step(o, False, label="primary")],
               expect=OUTCOME_APPROVAL_REJECTED, stage="APPROVAL")


def a2_post_approval_swap(rt, group, trial) -> Plan:
    # Approve exact args, capture material, then swap arguments at execute time.
    req = _base_req()
    jti = "jti-a2d-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    swapped = {"title": "Summary-REC-002", "content": "OVERWRITTEN_AFTER_APPROVAL"}
    swapped_req = build_action_request(tool_name="create_record", normalized_arguments=swapped)
    o = _auth(rt, POL_APPROVE, jti=jti, request_override=swapped_req, material_override=mat)
    return _mk(group=group, trial=trial, aid="A2d", name="A2 post-approval argument swap (digest mismatch)",
               task_input="content overwritten after approval before execution",
               tool="create_record", recv_args=ARGS_LEGAL, validated_args=swapped,
               steps=[Step(o, False, label="primary")],
               expect=OUTCOME_AUTHORIZATION_REJECTED, stage="H1_AUTHORIZATION",
               detail={"material_bound_content": ARGS_LEGAL["content"], "executed_content": swapped["content"]})


# ---------------------------------------------------------------------------
# A3: authorization-material replacement & forgery
# ---------------------------------------------------------------------------

def a3_forged_jti(rt, group, trial) -> Plan:
    req = _base_req()
    if group == "B2":
        mat = {"jti": "jti-FORGED-" + uuid.uuid4().hex, "action_digest": compute_action_digest(req)}
    else:
        mat = {"credential": {"payload": {}, "signature": "AAAA"},
               "jti": "jti-FORGED-" + uuid.uuid4().hex, "action_digest": compute_action_digest(req)}
    o = _auth(rt, POL_APPROVE, material_override=mat)
    return _mk(group=group, trial=trial, aid="A3a", name="A3 forged / nonexistent jti",
               task_input="attacker supplies a jti with no authorization record",
               tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
               steps=[Step(o, False, label="primary")],
               expect=OUTCOME_AUTHORIZATION_REJECTED, stage="H1_AUTHORIZATION")


def a3_action_digest_tamper(rt, group, trial) -> Plan:
    # B2's auth_ref.action_digest is only a pointer: frozen H1 recomputes the
    # digest from the request and queries the online service by jti. Tampering
    # the pointer field is therefore NOT a binding attack for B2. Record N/A
    # honestly rather than fabricate a "digest mismatch rejection".
    if group == "B2":
        return _mk(group=group, trial=trial, aid="A3b", name="A3 action_digest tamper (C-only vector)",
                   task_input="action_digest substitution — B2 auth_ref digest is only a pointer",
                   tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
                   steps=[], expect="NOT_APPLICABLE_B2_DIGEST_IS_POINTER", stage="N/A",
                   detail={"note": (
                       "B2 binding uses a recomputed digest + online jti query; the "
                       "auth_ref digest field is a pointer, not the binding source. "
                       "B2's real material-forgery surface is jti (A3a)."
                   )})
    # C: action_digest lives INSIDE the signed credential payload; flipping it
    # invalidates the Ed25519 signature (attributed as signature failure).
    req = _base_req()
    jti = "jti-a3b-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    bad = deepcopy(mat)
    bad["credential"]["payload"]["action_digest"] = "sha256:" + "f" * 64
    o = _auth(rt, POL_APPROVE, jti=jti, material_override=bad)
    return _mk(group=group, trial=trial, aid="A3b", name="A3 credential action_digest tamper",
               task_input="attacker flips signed action_digest inside the credential",
               tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
               steps=[Step(o, False, label="primary")],
               expect=OUTCOME_AUTHORIZATION_REJECTED, stage="H1_AUTHORIZATION",
               detail={"attribution": "signature covers payload; tamper -> C_SIGNATURE_INVALID"})


def a3_credential_tamper(rt, group, trial) -> Plan:
    if group == "B2":
        # B2 carries no Ed25519 credential; this vector is not applicable.
        return _mk(group=group, trial=trial, aid="A3c", name="A3 credential tamper (C-only vector)",
                   task_input="credential tamper — B2 has no Ed25519 credential",
                   tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
                   steps=[], expect="NOT_APPLICABLE_B2_NO_CREDENTIAL", stage="N/A",
                   detail={"note": "B2 carries no credential; verdict is N/A, not a pass/fail."})
    req = _base_req()
    jti = "jti-a3c-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    bad = deepcopy(mat)
    sig = bad["credential"]["signature"]
    bad["credential"]["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    o = _auth(rt, POL_APPROVE, jti=jti, material_override=bad)
    return _mk(group=group, trial=trial, aid="A3c", name="A3 credential signature tamper",
               task_input="attacker flips one signature character",
               tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
               steps=[Step(o, False, label="primary")],
               expect=OUTCOME_AUTHORIZATION_REJECTED, stage="H1_AUTHORIZATION")


def a3_unknown_key_id(rt, group, trial) -> Plan:
    if group == "B2":
        return _mk(group=group, trial=trial, aid="A3d", name="A3 unknown key_id (C-only vector)",
                   task_input="key_id tamper — B2 trusts no public keys",
                   tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
                   steps=[], expect="NOT_APPLICABLE_B2_NO_KEY_ID", stage="N/A",
                   detail={"note": "B2 has no key_id trust map; verdict is N/A."})
    req = _base_req()
    jti = "jti-a3d-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    bad = deepcopy(mat)
    bad["credential"]["payload"]["key_id"] = "h1-key-UNTRUSTED"
    o = _auth(rt, POL_APPROVE, jti=jti, material_override=bad)
    return _mk(group=group, trial=trial, aid="A3d", name="A3 unknown key_id",
               task_input="attacker sets key_id to an untrusted value",
               tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
               steps=[Step(o, False, label="primary")],
               expect=OUTCOME_AUTHORIZATION_REJECTED, stage="H1_AUTHORIZATION")


# ---------------------------------------------------------------------------
# A4: authorization replay
# ---------------------------------------------------------------------------

def a4_replay_same_jti(rt, group, trial) -> Plan:
    req = _base_req()
    jti = "jti-a4-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    # First use: valid, dispatch actually issued (real effect).
    first = _auth(rt, POL_APPROVE, jti=jti, material_override=mat)
    s1 = Step(first, first.get("dispatch_permitted", False), "create_record", dict(ARGS_LEGAL),
              label="first")
    # Replay same jti: must NOT get a fresh dispatch permission.
    second = _auth(rt, POL_APPROVE, jti=jti, material_override=mat)
    s2 = Step(second, False, label="primary")
    return _mk(group=group, trial=trial, aid="A4a", name="A4 same-jti replay",
               task_input="reuse a consumed authorization jti",
               tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
               steps=[s1, s2], primary_label="primary",
               expect=OUTCOME_REPLAY_REJECTED, stage="ONE_TIME_CONSUMPTION")


def a4_replay_diff_args(rt, group, trial) -> Plan:
    req = _base_req()
    jti = "jti-a4b-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    first = _auth(rt, POL_APPROVE, jti=jti, material_override=mat)
    s1 = Step(first, first.get("dispatch_permitted", False), "create_record", dict(ARGS_LEGAL), label="first")
    swapped = build_action_request(tool_name="create_record", normalized_arguments={"title": "PWNED", "content": "replay"})
    second = _auth(rt, POL_APPROVE, jti=jti, request_override=swapped, material_override=mat)
    s2 = Step(second, False, label="primary")
    return _mk(group=group, trial=trial, aid="A4b", name="A4 replayed jti + swapped args (digest binding)",
               task_input="reuse consumed jti with a different create_record payload",
               tool="create_record", recv_args=swapped.arguments if hasattr(swapped, "arguments") else ARGS_LEGAL,
               validated_args=ARGS_LEGAL, steps=[s1, s2], primary_label="primary",
               expect=OUTCOME_AUTHORIZATION_REJECTED, stage="H1_AUTHORIZATION",
               detail={"attribution": "action digest recomputed from swapped args mismatches the consumed credential; jti+args double-bound"})


def a4_replay_diff_tool(rt, group, trial) -> Plan:
    req = _base_req()
    jti = "jti-a4c-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    first = _auth(rt, POL_APPROVE, jti=jti, material_override=mat)
    s1 = Step(first, first.get("dispatch_permitted", False), "create_record", dict(ARGS_LEGAL), label="first")
    swapped = build_action_request(tool_name="update_record", normalized_arguments={"record_id": "REC-001", "content": "replayed"})
    second = _auth(rt, POL_APPROVE, jti=jti, request_override=swapped, material_override=mat)
    s2 = Step(second, False, label="primary")
    return _mk(group=group, trial=trial, aid="A4c", name="A4 replayed jti + swapped tool (digest binding)",
               task_input="reuse consumed jti for update_record",
               tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
               steps=[s1, s2], primary_label="primary",
               expect=OUTCOME_AUTHORIZATION_REJECTED, stage="H1_AUTHORIZATION",
               detail={"attribution": "tool_name is in the digest; swapped tool mismatches the consumed credential"})


# ---------------------------------------------------------------------------
# A5: execution-context substitution (credential must bind context, not just tool)
# ---------------------------------------------------------------------------

def _context_swap_case(rt, group, trial, aid, name, bad_req, desc):
    req = _base_req()
    jti = "jti-" + aid.lower() + "-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    o = _auth(rt, POL_APPROVE, jti=jti, request_override=bad_req, material_override=mat)
    return _mk(group=group, trial=trial, aid=aid, name=name, task_input=desc,
               tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
               steps=[Step(o, False, label="primary")],
               expect=OUTCOME_AUTHORIZATION_REJECTED, stage="H1_AUTHORIZATION")


def a5_server_uri(rt, group, trial):
    bad = ActionRequest(executor_id="h3-2-executor", server_uri="mcp://evil-store",
                        tool_name="create_record", schema_hash=SCHEMA_HASH, arguments=dict(ARGS_LEGAL))
    return _context_swap_case(rt, group, trial, "A5a", "A5 server_uri substitution",
                              bad, "attacker replaces server_uri with mcp://evil-store")


def a5_executor_id(rt, group, trial):
    bad = ActionRequest(executor_id="executor-attacker", server_uri=SERVER_URI,
                        tool_name="create_record", schema_hash=SCHEMA_HASH, arguments=dict(ARGS_LEGAL))
    return _context_swap_case(rt, group, trial, "A5b", "A5 executor_id substitution",
                              bad, "attacker replaces executor_id")


def a5_tool_name(rt, group, trial):
    bad = build_action_request(tool_name="update_record", normalized_arguments={"record_id": "REC-001", "content": "swapped"})
    return _context_swap_case(rt, group, trial, "A5c", "A5 tool_name substitution",
                              bad, "attacker swaps create_record -> update_record")


def a5_schema_hash(rt, group, trial):
    bad = ActionRequest(executor_id="h3-2-executor", server_uri=SERVER_URI,
                        tool_name="create_record", schema_hash="sha256:" + "0" * 64,
                        arguments=dict(ARGS_LEGAL))
    return _context_swap_case(rt, group, trial, "A5d", "A5 schema_hash substitution",
                              bad, "attacker replaces tool schema hash")


# ---------------------------------------------------------------------------
# A6: exceptional execution / audit (uncertain window, no auto-retry)
# ---------------------------------------------------------------------------

def a6_uncertain_no_retry(rt, group, trial):
    req = _base_req()
    jti = "jti-a6-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    # First: authorized + jti consumed, but MCP fails -> DISPATCH_UNCERTAIN.
    first = _auth(rt, POL_APPROVE, jti=jti, material_override=mat)
    s1 = Step(first, True, "create_record", dict(ARGS_LEGAL), force_mcp_failure=True, label="first")
    # Retry with the same jti: must NOT be granted a fresh dispatch.
    second = _auth(rt, POL_APPROVE, jti=jti, material_override=mat)
    s2 = Step(second, False, label="primary")
    return _mk(group=group, trial=trial, aid="A6", name="A6 consume-then-MCP-fail, no retry",
               task_input="MCP call fails after jti consumed; harness attempts retry",
               tool="create_record", recv_args=ARGS_LEGAL, validated_args=ARGS_LEGAL,
               steps=[s1, s2], primary_label="primary",
               expect=OUTCOME_DISPATCH_UNCERTAIN, stage="DISPATCH_UNCERTAIN",
               detail={"note": "jti spent before MCP outcome; no exactly-once claim; no auto-retry."})


# Ordered registry. Each builder: (rt, group, trial) -> Plan.
A2_CASES = [a2_legal_control, a2_schema_invalid, a2_approval_argument_swap, a2_post_approval_swap]
A3_CASES = [a3_forged_jti, a3_action_digest_tamper, a3_credential_tamper, a3_unknown_key_id]
A4_CASES = [a4_replay_same_jti, a4_replay_diff_args, a4_replay_diff_tool]
A5_CASES = [a5_server_uri, a5_executor_id, a5_tool_name, a5_schema_hash]
A6_CASES = [a6_uncertain_no_retry]

ALL_CASES = A2_CASES + A3_CASES + A4_CASES + A5_CASES + A6_CASES
