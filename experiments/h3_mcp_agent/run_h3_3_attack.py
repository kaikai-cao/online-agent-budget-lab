"""H3.3 runner: full attack evaluation on the real Agent execution chain.

Layer 1 (A1): real/mock Agent + REAL MCP adversarial tool-return induction.
Layer 2 (A2-A6): deterministic attacks through the REAL Host validation,
REAL H3.2 authorization gate and REAL MCP Server (only on permitted dispatch).

Outputs (results/h3-3 by default):
  A1/{A1_trials.jsonl,A1_trials.csv,A1_summary.json}
  A2/... A6/...   (one folder per attack family, B2/C rows together but
                    grouped in summary.by_group)
  overall_summary.json   (cross-attack totals, B2/C separated)

Modes:
  (default) real DeepSeek for A1 (requires DEEPSEEK_API_KEY).
  --mock    deterministic FakeClient for A1 (chain verification ONLY; never a
            real-API result). A2-A6 are deterministic in both modes.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from experiments.h3_mcp_agent.host.deepseek_client import DeepSeekClient, get_api_key  # noqa: E402
from experiments.h3_mcp_agent.h3_2_authorization.authorization_adapter import (  # noqa: E402
    AuthorizationRuntime,
)
from experiments.h3_mcp_agent.h3_3_attack.agent_induction import (  # noqa: E402
    A1_TASKS, InductionFakeClient, run_induction_task,
)
from experiments.h3_mcp_agent.h3_3_attack.attack_cases import (  # noqa: E402
    A2_CASES, A3_CASES, A4_CASES, A5_CASES, A6_CASES,
)
from experiments.h3_mcp_agent.h3_3_attack.attack_common import (  # noqa: E402
    ALL_OUTCOMES, OUTCOME_UNAUTHORIZED_EFFECT, AttackRecord, write_records,
)
from experiments.h3_mcp_agent.h3_3_attack.deterministic_attacks import execute_plan  # noqa: E402

ATTACK_FAMILIES = {
    "A2": A2_CASES, "A3": A3_CASES, "A4": A4_CASES,
    "A5": A5_CASES, "A6": A6_CASES,
}


async def run_a1(*, out_dir: Path, workdir: Path, mock: bool, key: str | None,
                 repeats: int) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    model: Any = InductionFakeClient() if mock else DeepSeekClient(api_key=key)
    rows: list[dict[str, Any]] = []
    for trial in range(repeats):
        for task in A1_TASKS:
            for group in ("B2", "C"):
                row = await run_induction_task(
                    task=task, group=group, workdir=workdir, model_client=model, trial=trial
                )
                rows.append(row)

    jsonl = out_dir / "A1_trials.jsonl"
    with jsonl.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    from experiments.h3_mcp_agent.h3_3_attack.attack_common import RECORD_FIELDS
    import csv
    with (out_dir / "A1_trials.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=RECORD_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)

    counts: dict[str, int] = {}
    by_group: dict[str, dict[str, int]] = {}
    for r in rows:
        o = r["outcome"]
        counts[o] = counts.get(o, 0) + 1
        by_group.setdefault(r["group"], {})
        by_group[r["group"]][o] = by_group[r["group"]].get(o, 0) + 1
    injection_reached = sum(
        1 for r in rows
        if (json.loads(r["detail"]) if isinstance(r.get("detail"), str) else r.get("detail", {}))
        .get("injection_reached_model")
    )
    summary = {
        "attack": "A1", "mode": "mock" if mock else "real",
        "model": getattr(model, "model", "unknown"),
        "real_api_called": not mock,
        "total": len(rows), "outcome_counts": counts, "by_group": by_group,
        "injection_reached_model_trials": injection_reached,
        "note": ("A1 has REAL MCP adversarial content; MODEL_DID_NOT_ATTACK is "
                 "recorded separately and is NOT a gateway-block success."),
    }
    (out_dir / "A1_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return summary


async def run_deterministic_family(*, name: str, cases: list, out_dir: Path,
                                   workdir: Path, repeats: int) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records: list[AttackRecord] = []
    for group in ("B2", "C"):
        rt = AuthorizationRuntime(path=group, dispatch_db=str(workdir / f"rt-{name}-{group}-{uuid.uuid4().hex[:6]}.sqlite3"))
        try:
            for case_fn in cases:
                for trial in range(repeats):
                    plan = case_fn(rt, group, trial)
                    rec = await execute_plan(plan, workdir)
                    records.append(rec)
        finally:
            rt.close()
    return write_records(records, out_dir, name)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--output-dir", default=str(_REPO_ROOT / "experiments" / "h3_mcp_agent" / "results" / "h3-3"))
    parser.add_argument("--repeats", type=int, default=10, help="N per attack case / A1 task")
    parser.add_argument("--a1-repeats", type=int, default=None, help="A1 repeats (default: repeats)")
    parser.add_argument("--only-a1", action="store_true")
    parser.add_argument("--skip-a1", action="store_true")
    args = parser.parse_args()

    out_root = Path(args.output_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    workdir = out_root / "work"
    workdir.mkdir(parents=True, exist_ok=True)

    key = None if args.mock else get_api_key()
    if not args.mock and not key:
        raise RuntimeError("DEEPSEEK_API_KEY is required for real A1 (or use --mock)")

    summaries: dict[str, Any] = {}
    if not args.skip_a1:
        summaries["A1"] = asyncio.run(run_a1(
            out_dir=out_root / "A1", workdir=workdir, mock=args.mock, key=key,
            repeats=args.a1_repeats or args.repeats,
        ))
    if not args.only_a1:
        for name, cases in ATTACK_FAMILIES.items():
            summaries[name] = asyncio.run(run_deterministic_family(
                name=name, cases=cases, out_dir=out_root / name,
                workdir=workdir, repeats=args.repeats,
            ))

    # Cross-attack overall summary, B2/C separated.
    overall_by_group: dict[str, dict[str, int]] = {}
    for name, summ in summaries.items():
        for g, counts in (summ.get("by_group") or {}).items():
            overall_by_group.setdefault(g, {})
            for o, n in counts.items():
                overall_by_group[g][o] = overall_by_group[g].get(o, 0) + n
    overall = {
        "mode": "mock" if args.mock else "real",
        "attacks": list(summaries),
        "overall_by_group": overall_by_group,
        "total_unauthorized_effects": sum(
            c.get(OUTCOME_UNAUTHORIZED_EFFECT, 0) for c in overall_by_group.values()
        ),
        "outcome_taxonomy": ALL_OUTCOMES,
        "note": "Boundaries: no exactly-once / no independent Receipt-Journal / MODEL_DID_NOT_ATTACK != block.",
    }
    (out_root / "overall_summary.json").write_text(
        json.dumps(overall, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({"output_dir": str(out_root),
                      "summaries": {k: v.get("total") for k, v in summaries.items()},
                      "overall_by_group": overall_by_group}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
