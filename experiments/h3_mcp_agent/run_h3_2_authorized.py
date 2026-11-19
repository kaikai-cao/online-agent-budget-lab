"""H3.2 runner: B2/C authorization on the real DeepSeek -> MCP Agent chain.

Groups:
  B2 -- frozen H1 Executor.execute_b2 over real pinned-TLS online query.
  C  -- frozen H1 Executor.execute_c via local Ed25519 verification.

Both groups share the same model/prompt/tasks/tools/normalization/approver and
the same DispatchConsumptionStore rules. The ONLY difference is the
verification path. The model never supplies jti/credential/approval.

Modes:
  (default) real DeepSeek API via DEEPSEEK_API_KEY.
  --mock     offline FakeClient (no API). Used for chain/mechanism verification;
             NEVER counted as a real-API result.

Outputs (results/h3-2 by default):
  B2/trials.jsonl, B2/summary.{json,csv}
  C/trials.jsonl,  C/summary.{json,csv}
  paired_summary.{csv,json}   (per task: B2 vs C paired view)
  mechanism/trials.csv, mechanism/summary.json  (M1-M11 x N repeats)

Each task uses an independent run_id and an isolated SQLite test DB. Full model
responses are saved; the two groups are independent DeepSeek calls, so tool
calls are NOT assumed identical.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from experiments.h3_mcp_agent.host.agent import AgentHost  # noqa: E402
from experiments.h3_mcp_agent.host.deepseek_client import (  # noqa: E402
    DeepSeekClient,
    get_api_key,
)
from experiments.h3_mcp_agent.host.mcp_client import McpClient  # noqa: E402
from experiments.h3_mcp_agent.logger import JsonlLogger  # noqa: E402
from experiments.h3_mcp_agent.redact import redact  # noqa: E402
from experiments.h3_mcp_agent.server.store import TestStore  # noqa: E402
from experiments.h3_mcp_agent.run_experiment import FakeClient, _load_tasks  # noqa: E402
from experiments.h3_mcp_agent.h3_2_authorization.approval_policy import ApprovalPolicy  # noqa: E402
from experiments.h3_mcp_agent.h3_2_authorization.authorization_adapter import (  # noqa: E402
    AuthorizationRuntime,
)
from experiments.h3_mcp_agent.h3_2_authorization.mechanism_matrix import (  # noqa: E402
    SCENARIOS,
    run_all as run_mechanism_all,
)

WRITE_TOOLS = {"create_record", "update_record"}


def _perf_stats(values: list[float]) -> dict[str, Any]:
    vals = sorted(v for v in values if isinstance(v, (int, float)))
    if not vals:
        return {"n": 0, "mean_ms": None, "median_ms": None, "p95_ms": None}
    n = len(vals)
    mean = sum(vals) / n
    median = vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2
    p95 = vals[min(n - 1, int(0.95 * n) + (1 if 0.95 * n > int(0.95 * n) else 0) - 1)]
    return {
        "n": n,
        "mean_ms": round(mean, 4),
        "median_ms": round(median, 4),
        "p95_ms": round(p95, 4),
    }


async def _run_one_task(
    *,
    task: dict[str, Any],
    scenario: str,
    group: str,
    runtime: AuthorizationRuntime,
    model_client: Any,
    policy: ApprovalPolicy,
    main_logger: JsonlLogger,
    workdir: Path,
) -> dict[str, Any]:
    run_id = "h32_" + group + "_" + scenario + "_" + uuid.uuid4().hex[:10]
    db_path = workdir / f"{run_id}.sqlite3"
    dispatch_db = workdir / f"dispatch-{run_id}.sqlite3"

    # A per-task runtime would re-sign keys; instead we reuse the group runtime
    # but use a per-task DispatchConsumptionStore so jti consumption is isolated
    # and observable per task.
    runtime.reset_dispatch_store(dispatch_db)

    main_events: list[dict[str, Any]] = []
    gate_events: list[dict[str, Any]] = []

    def collect_main(e: dict[str, Any]) -> None:
        main_events.append(e)
        main_logger.write({**e, "run_id": run_id, "scenario": scenario, "group": group, "model": model_client.model})

    def collect_gate(e: dict[str, Any]) -> None:
        gate_events.append(e)
        main_logger.write({**e, "run_id": run_id, "scenario": scenario, "group": group, "model": model_client.model})

    host = AgentHost(
        model_client,
        max_rounds=6,
        event_sink=collect_main,
        authorization_gate=runtime,
        authorization_required=True,
        gate_context={"group": group},
        gate_sink=collect_gate,
        task_policy=policy,
    )

    error = None
    answer = None
    rounds = 0
    try:
        async with McpClient(db_path, repo_root=_REPO_ROOT).session() as session:
            result = await host.run_task(session, task_id=task["task_id"], prompt=task["prompt"])
            answer = result["final_answer"]
            rounds = result["rounds"]
    except Exception as exc:  # honest recording
        error = type(exc).__name__ + ": " + str(exc)
        main_logger.write({"run_id": run_id, "task_id": task["task_id"], "scenario": scenario,
                           "group": group, "model": model_client.model, "event": "error",
                           "error": error, "timestamp": time.time()})

    store = TestStore(db_path)
    effects = store.count_effects()

    tool_events = [e for e in main_events if e.get("event") == "tool_call"]
    verified = [e for e in gate_events if e.get("event") == "authorization_verified"]
    rejected = [e for e in gate_events if e.get("event") == "authorization_rejected"]
    consumed = [e for e in gate_events if e.get("event") == "dispatch_consumed"]
    uncertain = [e for e in gate_events if e.get("event") == "dispatch_uncertain"]
    approvals = [e.get("approval") for e in gate_events if e.get("event") == "approval_decision"]
    approval_decisions = [a.get("reason") for a in approvals if isinstance(a, dict)]

    return {
        "run_id": run_id,
        "task_id": task["task_id"],
        "scenario": scenario,
        "group": group,
        "model": model_client.model,
        "write_tool_calls": sum(1 for e in tool_events if e.get("tool_name") in WRITE_TOOLS),
        "tool_calls": len(tool_events),
        "authorization_verified": len(verified),
        "authorization_rejected": len(rejected),
        "jti_consumed": len(consumed),
        "dispatch_uncertain": len(uncertain),
        "approval_decisions": approval_decisions,
        "authorization_latencies_ms": [e.get("verification_latency_ms") for e in verified],
        "consumption_latencies_ms": [e.get("consumption_latency_ms") for e in consumed],
        "mcp_received": sum(1 for e in tool_events if e.get("mcp_received") is True),
        "side_effects": effects,
        "final_answer": answer,
        "error": error,
        "rounds": rounds,
    }


async def _run_group(
    *,
    group: str,
    out_dir: Path,
    mock: bool,
    api_key: str | None,
    n_benign: int,
    n_injection: int,
    workdir: Path,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    policy = ApprovalPolicy()
    runtime = AuthorizationRuntime(path=group, dispatch_db=workdir / f"runtime-{group}-{uuid.uuid4().hex}.sqlite3")
    model: Any = FakeClient() if mock else DeepSeekClient(api_key=api_key)
    tasks = [("benign", t) for t in _load_tasks("benign")[:n_benign]]
    tasks += [("injection", t) for t in _load_tasks("injection")[:n_injection]]

    rows: list[dict[str, Any]] = []
    try:
        with JsonlLogger(out_dir / "trials.jsonl", api_key=api_key) as logger:
            for scenario, task in tasks:
                row = await _run_one_task(
                    task=task, scenario=scenario, group=group, runtime=runtime,
                    model_client=model, policy=policy, main_logger=logger, workdir=workdir,
                )
                rows.append(row)
    finally:
        runtime.close()

    fields = ["run_id", "task_id", "scenario", "group", "model", "tool_calls",
              "authorization_verified", "authorization_rejected", "jti_consumed",
              "dispatch_uncertain", "mcp_received", "side_effects", "final_answer", "error", "rounds"]
    with (out_dir / "summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(redact(r))

    verify_vals = [v for r in rows for v in r["authorization_latencies_ms"] if isinstance(v, (int, float))]
    consume_vals = [v for r in rows for v in r["consumption_latencies_ms"] if isinstance(v, (int, float))]
    summary = {
        "group": group,
        "mode": "mock" if mock else "real",
        "model": model.model,
        "real_api_called": not mock,
        "total_tasks": len(rows),
        "tasks_with_error": sum(1 for r in rows if r["error"]),
        "tool_calls": sum(r["tool_calls"] for r in rows),
        "authorization_verified": sum(r["authorization_verified"] for r in rows),
        "authorization_rejected": sum(r["authorization_rejected"] for r in rows),
        "jti_consumed": sum(r["jti_consumed"] for r in rows),
        "dispatch_uncertain": sum(r["dispatch_uncertain"] for r in rows),
        "mcp_received": sum(r["mcp_received"] for r in rows),
        "side_effects": sum(r["side_effects"] for r in rows),
        "authorization_latency_ms": _perf_stats(verify_vals),
        "consumption_latency_ms": _perf_stats(consume_vals),
        "tasks": redact(rows),
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def _write_paired(out_root: Path, b2: dict[str, Any], c: dict[str, Any]) -> None:
    by_id = {}
    for grp, summ in (("B2", b2), ("C", c)):
        for t in summ["tasks"]:
            key = (t["scenario"], t["task_id"])
            by_id.setdefault(key, {})[grp] = t
    rows = []
    for (scenario, task_id), pair in sorted(by_id.items()):
        b = pair.get("B2", {})
        cc = pair.get("C", {})
        rows.append({
            "scenario": scenario, "task_id": task_id,
            "b2_authorization_verified": b.get("authorization_verified"),
            "c_authorization_verified": cc.get("authorization_verified"),
            "b2_authorization_rejected": b.get("authorization_rejected"),
            "c_authorization_rejected": cc.get("authorization_rejected"),
            "b2_side_effects": b.get("side_effects"),
            "c_side_effects": cc.get("side_effects"),
            "b2_error": b.get("error"), "c_error": cc.get("error"),
            "same_tool_calls": (b.get("tool_calls") == cc.get("tool_calls")),
        })
    fields = list(rows[0].keys()) if rows else ["scenario", "task_id"]
    with (out_root / "paired_summary.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    (out_root / "paired_summary.json").write_text(
        json.dumps({"paired": rows, "note": "Independent DeepSeek calls; tool_calls may differ."},
                   ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--output-dir", default=str(_REPO_ROOT / "experiments" / "h3_mcp_agent" / "results" / "h3-2"))
    parser.add_argument("--n-benign", type=int, default=10)
    parser.add_argument("--n-injection", type=int, default=10)
    parser.add_argument("--mechanism-repeats", type=int, default=10)
    parser.add_argument("--skip-mechanism", action="store_true")
    args = parser.parse_args()

    out_root = Path(args.output_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    workdir = out_root / "work"
    workdir.mkdir(parents=True, exist_ok=True)

    key = None if args.mock else get_api_key()
    if not args.mock and not key:
        raise RuntimeError("DEEPSEEK_API_KEY is required for a real H3.2 run (or use --mock)")

    b2 = asyncio.run(_run_group(group="B2", out_dir=out_root / "B2", mock=args.mock,
                                api_key=key, n_benign=args.n_benign,
                                n_injection=args.n_injection, workdir=workdir))
    c = asyncio.run(_run_group(group="C", out_dir=out_root / "C", mock=args.mock,
                               api_key=key, n_benign=args.n_benign,
                               n_injection=args.n_injection, workdir=workdir))
    _write_paired(out_root, b2, c)

    if not args.skip_mechanism:
        mech_out = out_root / "mechanism"
        mech_out.mkdir(parents=True, exist_ok=True)
        mech_rows = run_mechanism_all(mech_out / "work", repeats=args.mechanism_repeats)
        with (mech_out / "trials.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["scenario", "group", "repeat", "pass", "detail"])
            w.writeheader()
            for r in mech_rows:
                w.writerow({"scenario": r["scenario"], "group": r["group"],
                            "repeat": r["repeat"], "pass": r["pass"],
                            "detail": json.dumps(r["detail"], ensure_ascii=False)})
        passed = sum(1 for r in mech_rows if r["pass"] == "TRUE")
        (mech_out / "summary.json").write_text(json.dumps({
            "total": len(mech_rows), "passed": passed, "failed": len(mech_rows) - passed,
            "scenarios": [s[0] for s in SCENARIOS], "repeats": args.mechanism_repeats,
        }, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps({
        "output_dir": str(out_root), "mode": "mock" if args.mock else "real",
        "B2": {k: b2[k] for k in ("total_tasks", "tasks_with_error", "authorization_verified",
                                  "authorization_rejected", "jti_consumed", "side_effects")},
        "C": {k: c[k] for k in ("total_tasks", "tasks_with_error", "authorization_verified",
                                "authorization_rejected", "jti_consumed", "side_effects")},
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
