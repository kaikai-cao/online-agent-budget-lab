"""Deterministic M1-M11 mechanism matrix for H3.2.

These are LOCAL, model-free tests of the authorization mechanism (B2/C), not
statistical security proofs and not DeepSeek runs. Each scenario builds a fresh
AuthorizationRuntime and records ACTUAL observed outcomes. Used by both the
unit tests and the experiment runner (which repeats each scenario N times).
"""

from __future__ import annotations

import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

from .approval_policy import ApprovalPolicy
from .authorization_adapter import PATH_B2, PATH_C, AuthorizationRuntime
from .experiment_config import SCHEMA_HASH, SERVER_URI, build_action_request
from .h1_bridge import (
    CredentialIssuanceError,
    VerificationError,
    action_identity,
    compute_action_digest,
)

TASK_ID = "B03"  # policy approves create_record for this benign task
ARGS = {"title": "t", "content": "c"}

# (id, description, b2 expectation, c expectation)
SCENARIOS: list[tuple[str, str, str, str]] = [
    ("M1", "fully matching valid authorization", "ALLOW", "ALLOW"),
    ("M2", "no authorization record / no credential", "DENY", "DENY"),
    ("M3", "arguments modified after approval", "DENY", "DENY"),
    ("M4", "tool_name substituted", "DENY", "DENY"),
    ("M5", "server_uri or executor_id substituted", "DENY", "DENY"),
    ("M6", "same jti replayed", "NO_REDISPATCH", "NO_REDISPATCH"),
    ("M7", "revoked after issuance", "DENY_ONLINE", "ALLOW_OFFLINE"),
    ("M8", "authorization service unavailable", "DENY_ONLINE", "ALLOW_OFFLINE"),
    ("M9", "expired credential/authorization", "DENY", "DENY"),
    ("M10", "C signature tamper / unknown key_id", "N/A", "DENY"),
    ("M11", "jti consumed then MCP fails (uncertain)", "UNCERTAIN_NO_RETRY", "UNCERTAIN_NO_RETRY"),
]


def _req(**kwargs: Any):
    base = {"tool_name": "create_record", "normalized_arguments": dict(ARGS)}
    base.update(kwargs)
    return build_action_request(
        tool_name=base["tool_name"], normalized_arguments=base["normalized_arguments"]
    )


def _authorize(rt: AuthorizationRuntime, policy: ApprovalPolicy, **kwargs: Any):
    return rt.authorize(policy=policy, task_id=TASK_ID, group=rt.path, **kwargs)


def _run_m1(rt, pol):
    out = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS)
    ok = out.status == "AUTHORIZED" and out.dispatch_permitted and rt.dispatcher.consumption_count() == 1
    return out.as_dict(), ok


def _run_m2(rt, pol):
    if rt.path == PATH_B2:
        mat = {"jti": "jti-NONEXISTENT-" + uuid.uuid4().hex, "action_digest": compute_action_digest(_req())}
        out = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, material_override=mat)
    else:
        mat = {"credential": {"payload": {}, "signature": "AAAA"}}
        out = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, material_override=mat)
    ok = out.status != "AUTHORIZED" and not out.dispatch_permitted and rt.dispatcher.consumption_count() == 0
    return out.as_dict(), ok


def _run_m3(rt, pol):
    req = _req()
    jti = "jti-m3-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    tampered = _req(normalized_arguments={"title": "t", "content": "TAMPERED"})
    out = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS,
                     jti=jti, request_override=tampered, material_override=mat)
    ok = out.status != "AUTHORIZED" and not out.dispatch_permitted and rt.dispatcher.consumption_count() == 0
    return out.as_dict(), ok


def _run_m4(rt, pol):
    req = _req()
    jti = "jti-m4-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    swapped = _req(tool_name="update_record", normalized_arguments={"record_id": "REC-001", "content": "x"})
    out = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS,
                     jti=jti, request_override=swapped, material_override=mat)
    ok = out.status != "AUTHORIZED" and not out.dispatch_permitted and rt.dispatcher.consumption_count() == 0
    return out.as_dict(), ok


def _run_m5(rt, pol):
    from .h1_bridge import ActionRequest

    req = _req()
    jti = "jti-m5-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    # executor_id substitution
    bad_exec = ActionRequest(executor_id="executor-attacker", server_uri=SERVER_URI,
                             tool_name="create_record", schema_hash=SCHEMA_HASH, arguments=dict(ARGS))
    out1 = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS,
                      jti=jti, request_override=bad_exec, material_override=mat)
    # server_uri substitution (digest changes -> mismatch)
    bad_uri = ActionRequest(executor_id="h3-2-executor", server_uri="mcp://evil-store",
                            tool_name="create_record", schema_hash=SCHEMA_HASH, arguments=dict(ARGS))
    jti2 = "jti-m5b-" + uuid.uuid4().hex
    mat2 = rt._confirm_and_material(request=req, jti=jti2)
    out2 = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS,
                      jti=jti2, request_override=bad_uri, material_override=mat2)
    ok = (out1.status != "AUTHORIZED" and out2.status != "AUTHORIZED"
          and rt.dispatcher.consumption_count() == 0)
    return {"executor_sub": out1.as_dict(), "uri_sub": out2.as_dict()}, ok


def _run_m6(rt, pol):
    req = _req()
    jti = "jti-m6-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    out1 = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, jti=jti, material_override=mat)
    out2 = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, jti=jti, material_override=mat)
    ok = (out1.status == "AUTHORIZED" and out1.dispatch_permitted
          and not out2.dispatch_permitted
          and rt.dispatcher.consumption_count() == 1
          and rt.dispatcher.event_counts().get("DISPATCH_SKIPPED", 0) >= 1)
    return {"first": out1.as_dict(), "second": out2.as_dict(),
            "consumptions": rt.dispatcher.consumption_count(), "events": rt.dispatcher.event_counts()}, ok


def _run_m7(rt, pol):
    req = _req()
    jti = "jti-m7-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    rt.revoke(jti)
    out = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, jti=jti, material_override=mat)
    if rt.path == PATH_B2:
        ok = out.status != "AUTHORIZED" and "REVOKED" in out.reason and not out.dispatch_permitted
    else:
        ok = out.status == "AUTHORIZED" and out.dispatch_permitted  # offline cannot see revocation
    return out.as_dict(), ok


def _run_m8(rt, pol):
    req = _req()
    jti = "jti-m8-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)  # issue while service up
    rt.stop_service()
    out = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, jti=jti, material_override=mat)
    if rt.path == PATH_B2:
        ok = out.status != "AUTHORIZED" and "UNREACHABLE" in out.reason and not out.dispatch_permitted
    else:
        ok = out.status == "AUTHORIZED" and out.dispatch_permitted  # local verify offline
    return out.as_dict(), ok


def _run_m9(rt, pol):
    req_map = action_identity(_req())
    jti = "jti-m9-" + uuid.uuid4().hex
    t0 = time.time()
    rt.service.confirm(request=req_map, jti=jti, ttl_seconds=-1.0, now=t0)
    if rt.path == PATH_B2:
        mat = {"jti": jti, "action_digest": compute_action_digest(req_map)}
        out = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, material_override=mat)
        ok = out.status != "AUTHORIZED" and "EXPIRED" in out.reason and not out.dispatch_permitted
        return out.as_dict(), ok
    # C: expired record is refused at the trusted issuance entry (H1 guard).
    try:
        rt.service.issue_credential(jti, now=t0)
        detail = {"status": "UNEXPECTEDLY_ISSUED", "reason": "ISSUANCE_GUARD_FAILED"}
        ok = False
    except CredentialIssuanceError as exc:
        detail = {"status": "AUTHORIZATION_REJECTED", "reason": f"CREDENTIAL_ISSUANCE_REFUSED:{exc.reason}"}
        ok = exc.reason == "EXPIRED"
    return detail, ok


def _run_m10(rt, pol):
    if rt.path == PATH_B2:
        return {"status": "N/A", "reason": "B2_CARRIES_NO_ED25519_CREDENTIAL"}, True
    req = _req()
    jti = "jti-m10-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    bad_sig = deepcopy(mat)
    bad_sig["credential"] = deepcopy(mat["credential"])
    sig = bad_sig["credential"]["signature"]
    bad_sig["credential"]["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    out1 = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, jti=jti, material_override=bad_sig)
    bad_key = deepcopy(mat)
    bad_key["credential"] = deepcopy(mat["credential"])
    bad_key["credential"]["payload"] = dict(mat["credential"]["payload"])
    bad_key["credential"]["payload"]["key_id"] = "h1-key-UNTRUSTED"
    out2 = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, jti=jti, material_override=bad_key)
    ok = (out1.status != "AUTHORIZED" and "SIGNATURE" in out1.reason
          and out2.status != "AUTHORIZED" and "KEY_ID" in out2.reason)
    return {"signature_tamper": out1.as_dict(), "unknown_key_id": out2.as_dict()}, ok


def _run_m11(rt, pol):
    # First authorization consumes jti; then MCP is assumed to have failed
    # (recorded as DISPATCH_UNCERTAIN). No auto-retry: a second authorize with
    # the same jti must NOT grant a fresh dispatch. Host-level MCP-failure
    # handling is covered by the AgentHost integration test.
    req = _req()
    jti = "jti-m11-" + uuid.uuid4().hex
    mat = rt._confirm_and_material(request=req, jti=jti)
    out1 = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, jti=jti, material_override=mat)
    rt.dispatcher.record_dispatch_outcome(jti, "DISPATCH_UNCERTAIN", "MCP_ERROR_ASSUMED")
    out2 = _authorize(rt, pol, tool_name="create_record", normalized_arguments=ARGS, jti=jti, material_override=mat)
    ok = (out1.status == "AUTHORIZED" and out1.dispatch_permitted
          and not out2.dispatch_permitted
          and rt.dispatcher.consumption_count() == 1
          and "DISPATCH_UNCERTAIN" in rt.dispatcher.event_counts())
    return {"first": out1.as_dict(), "retry": out2.as_dict(), "events": rt.dispatcher.event_counts()}, ok


_RUNNERS: dict[str, Callable[[AuthorizationRuntime, ApprovalPolicy], tuple[Any, bool]]] = {
    "M1": _run_m1, "M2": _run_m2, "M3": _run_m3, "M4": _run_m4, "M5": _run_m5,
    "M6": _run_m6, "M7": _run_m7, "M8": _run_m8, "M9": _run_m9, "M10": _run_m10, "M11": _run_m11,
}


def run_one(scenario_id: str, path: str, workdir: Path, repeat: int = 0) -> dict[str, Any]:
    """Run one (scenario, path) case with a FRESH runtime; return observed row."""
    pol = ApprovalPolicy()
    tag = f"{scenario_id}-{path}-{repeat}-{uuid.uuid4().hex[:6]}"
    rt = AuthorizationRuntime(path=path, dispatch_db=workdir / f"dispatch-{tag}.sqlite3")
    try:
        detail, ok = _RUNNERS[scenario_id](rt, pol)
    finally:
        rt.close()
    return {
        "scenario": scenario_id,
        "group": path,
        "repeat": repeat,
        "pass": "TRUE" if ok else "FALSE",
        "detail": detail,
    }


def run_all(workdir: Path, repeats: int = 10) -> list[dict[str, Any]]:
    workdir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for sid, _desc, _b2, _c in SCENARIOS:
        for path in (PATH_B2, PATH_C):
            for i in range(repeats):
                rows.append(run_one(sid, path, workdir, i))
    return rows
