"""Run the full R2.4 Phase-2 discrimination matrix and write result artifacts.

Produces:
  results/raw_results.jsonl       - 50 trial records (5 scenarios x 10 trials)
  results/summary.json            - four metrics per scheme + expected conformance
  results/experiment_report.md    - facts, GO/NO-GO evidence, honesty boundaries

The four metrics are computed by the CONTROLLER: it compares each verifier's
verdicts (observable evidence only) to the recorded ground truth. The verifier
never receives ground truth. See models.assert_no_ground_truth / verifier.py.

No ZKP/Halo2/TEE/Merkle. No token/CPU/GPU metering. No billing/payment.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from r24p2.scenarios import (  # noqa: E402
    BASE_SEED, EXPECTED, SCENARIOS, TRIALS, run_trial,
)
from r24p2.verifier import SCHEMES  # noqa: E402

RESULTS = ROOT / "results"
RAW = RESULTS / "raw_results.jsonl"
SUMMARY = RESULTS / "summary.json"
REPORT = RESULTS / "experiment_report.md"
CONFIG = ROOT / "configs" / "experiment.yaml"


def load_config() -> dict:
    # configs/experiment.yaml is YAML 1.2 (JSON superset); stdlib json suffices.
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def verdict_results(scheme_block: dict) -> list[dict]:
    """One verdict per (logical_call_id, attempt_id), deduplicated by key.

    A duplicate submission yields several raw verdict rows with the same key;
    billing/coverage must count a call once. We keep the most decisive row per
    key by priority (COVERED > UNCERTAIN > MISSING_EVIDENCE >
    DUPLICATE_IGNORED > BYPASS_DETECTED > NO_EVIDENCE). For metric purposes we
    count DISTINCT call keys with a given result.
    """
    by_key: dict[tuple[str, str], list[dict]] = {}
    for v in scheme_block["verdicts"]:
        by_key.setdefault((v["logical_call_id"], v["attempt_id"]), []).append(v)
    out = []
    for k, rows in by_key.items():
        results = {r["result"] for r in rows}
        # representative result: prefer COVERED if any row is COVERED, etc.
        priority = ["COVERED", "UNCERTAIN", "MISSING_EVIDENCE",
                    "DUPLICATE_IGNORED", "BYPASS_DETECTED", "NO_EVIDENCE"]
        rep = next(p for p in priority if p in results) if results else "NO_EVIDENCE"
        out.append({
            "logical_call_id": k[0], "attempt_id": k[1],
            "result": rep, "all_results": sorted(results),
        })
    return out


def compute_metrics(records: list[dict]) -> dict:
    """Controller-side scoring against ground truth (verifier never sees GT)."""
    metrics = {s: {
        "execution_coverage": {"covered": 0, "executed": 0, "rate": None},
        "missing_report_detection": {"detected": 0, "suppressed": 0, "rate": None},
        "duplicate_metering_error": {"errors": 0, "trials": 0},
        "uncertain_state_correctness": {"correct": 0, "trials": 0, "rate": None},
    } for s in SCHEMES}

    for rec in records:
        sc = rec["scenario"]
        for sch in SCHEMES:
            block = rec["schemes"][sch]
            gt = block["ground_truth"]
            vres = verdict_results(block)
            v_by_key = {(v["logical_call_id"], v["attempt_id"]): v for v in vres}

            # --- execution coverage: GT-executed logical calls that have an
            # evidence anchor under the scheme. Join by logical_call_id (NOT by
            # attempt): P0 has no attempt tracking, so its verdict attempt is ""
            # while ground truth carries real attempts — joining by attempt would
            # spuriously report 0% coverage for P0 even where it has a valid
            # service self-report. Attempt-level correctness is the SEPARATE
            # duplicate-metering-error metric; do not fold it into coverage.
            # An anchor = any non-NO_EVIDENCE verdict for that logical call.
            # Rejected bypass (service_executed=False) is excluded from the
            # denominator — a rejected request never entered the exec boundary.
            anchored_calls = {
                v["logical_call_id"] for v in vres
                if v["result"] not in {"NO_EVIDENCE"}
            }
            executed_calls = {
                g["logical_call_id"] for g in gt if g["service_executed"]
            }
            m = metrics[sch]["execution_coverage"]
            for _call in executed_calls:
                m["executed"] += 1
                if _call in anchored_calls:
                    m["covered"] += 1

            # --- missing report detection (T3 suppressed reports) ---
            if sc == "T3":
                m2 = metrics[sch]["missing_report_detection"]
                m2["suppressed"] += 1
                # P0 has no anchor -> no verdict; schemes that flag MISSING_EVIDENCE
                if any(v["result"] == "MISSING_EVIDENCE" for v in vres):
                    m2["detected"] += 1

            # --- duplicate metering error (T4) ---
            if sc == "T4":
                m3 = metrics[sch]["duplicate_metering_error"]
                m3["trials"] += 1
                executed_n = sum(1 for g in gt if g["service_executed"])
                billed_n = sum(
                    1 for v in vres
                    if v["result"] in {"COVERED", "DUPLICATE_IGNORED"}
                )
                if billed_n != executed_n:
                    m3["errors"] += 1

            # --- uncertain-state correctness (T5) ---
            if sc == "T5":
                m4 = metrics[sch]["uncertain_state_correctness"]
                m4["trials"] += 1
                if any(v["result"] == "UNCERTAIN" for v in vres):
                    m4["correct"] += 1
                elif all(v["result"] == "COVERED" for v in vres):
                    pass  # counted as incorrect (silently complete)
                # P0/P1 have no observer in their stack -> also not correct here.

    for sch in SCHEMES:
        c = metrics[sch]["execution_coverage"]
        c["rate"] = round(c["covered"] / c["executed"], 4) if c["executed"] else None
        d = metrics[sch]["missing_report_detection"]
        d["rate"] = round(d["detected"] / d["suppressed"], 4) if d["suppressed"] else None
        u = metrics[sch]["uncertain_state_correctness"]
        u["rate"] = round(u["correct"] / u["trials"], 4) if u["trials"] else None
    return metrics


def expected_conformance(records: list[dict]) -> dict:
    """Check actual verdict-result sets against the pre-registered matrix."""
    out = {sc: {s: {"expected": EXPECTED[sc][s], "conform": 0, "total": 0}
                for s in SCHEMES} for sc in SCENARIOS}
    for rec in records:
        sc = rec["scenario"]
        for sch in SCHEMES:
            actual = {v["result"] for v in verdict_results(rec["schemes"][sch])}
            exp = set(EXPECTED[sc][sch])
            cell = out[sc][sch]
            cell["total"] += 1
            if exp == actual:
                cell["conform"] += 1
    return out


def write_report(metrics: dict, conformance: dict, n: int, cfg: dict) -> None:
    L = []
    L.append("# R2.4 Phase 2 — Gateway Enforcement vs. Independent Metering Coverage")
    L.append("")
    L.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    L.append(f"Seed base: {BASE_SEED} · trials/scenario: {TRIALS} · raw records: {n}")
    L.append("")
    L.append("## Purpose (discrimination, NOT a proof)")
    L.append("")
    L.append("This experiment asks what mandatory gateway enforcement, ingress observation "
             "and witness/observer evidence each ADD in coverage terms. It is designed to "
             "allow a NO-GO result: if a simple enforcement gateway already covers the "
             "target scenarios, that is reported honestly rather than packaging complexity "
             "as research value.")
    L.append("")
    L.append("## Scope boundaries")
    L.append("")
    L.append("- IN: tool-call counts, ingress receipt, call linkage, uncertain-state on "
             "missing observation.")
    L.append("- OUT: token/CPU/GPU metering, cross-domain delegation, real TEE/attestation, "
             "Halo2/ZKP, pricing/billing/payment. See configs/experiment.yaml.")
    L.append("")
    L.append("## Schemes")
    L.append("")
    for s in SCHEMES:
        L.append(f"- **{s}** — {cfg['scheme_composition'][s]}")
    L.append("")
    L.append("## Isolation & honesty guards")
    L.append("")
    L.append("- P1 is a REAL mandatory gateway: the service entrance authenticates a "
             "gateway-SIGNED receipt with the gateway public key; a direct/bypass call is "
             "rejected and never executes (test_gateway_enforcement.py).")
    L.append("- `service_executed` (ground truth) is recorded by the controller only and "
             "is NEVER a verifier input; verifier functions accept only signed observable "
             "records, and assert_no_ground_truth enforces it (test_missing_report.py).")
    L.append("- Gateway FORWARD receipt proves traversal, NOT execution: a forwarded-but-"
             "unreported call is MISSING_EVIDENCE, never COVERED.")
    L.append("- service_acceptance != service_execution; a recorded row != a complete/"
             "true record; an observer row != observation of all paths.")
    L.append("")
    L.append("## Four metrics (kept separate)")
    L.append("")
    L.append("| Scheme | Execution coverage | Missing-report detection | Duplicate-metering errors | Uncertain-state correctness |")
    L.append("| --- | --- | --- | --- | --- |")
    for s in SCHEMES:
        c = metrics[s]["execution_coverage"]
        d = metrics[s]["missing_report_detection"]
        e = metrics[s]["duplicate_metering_error"]
        u = metrics[s]["uncertain_state_correctness"]
        cov = "N/A" if c["rate"] is None else f"{c['covered']}/{c['executed']} = {c['rate']:.0%}"
        det = "N/A" if d["rate"] is None else f"{d['detected']}/{d['suppressed']} = {d['rate']:.0%}"
        unc = "N/A" if u["rate"] is None else f"{u['correct']}/{u['trials']} = {u['rate']:.0%}"
        L.append(f"| {s} | {cov} | {det} | {e['errors']} / {e['trials']} trials | {unc} |")
    L.append("")
    L.append("Metric definitions:")
    for k, v in cfg["metrics"].items():
        L.append(f"- `{k}`: {v}")
    L.append("")
    L.append("## Pre-registered expectation conformance (50 trials)")
    L.append("")
    L.append("Expected matrix is a hypothesis, NOT an obtained result.")
    L.append("")
    L.append("| Scenario | Scheme | Expected | Conform / total |")
    L.append("| --- | --- | --- | --- |")
    for sc in SCENARIOS:
        for s in SCHEMES:
            cell = conformance[sc][s]
            L.append(f"| {sc} | {s} | {', '.join(cell['expected']) or '(none)'} | "
                     f"{cell['conform']}/{cell['total']} |")
    L.append("")
    L.append("## Key scenario facts")
    L.append("")
    L.append("- T2 bypass: P1 rejects at the entrance (service_executed=False), so the "
             "bypassed request is NOT counted as a successful execution. P2/P3 additionally "
             "observe the unauthenticated entrance request (BYPASS_DETECTED). P0 has no "
             "gateway and cannot see the bypass.")
    L.append("- T3 no-report: the service executed but submitted nothing. P1 flags the "
             "gateway-forward/evidence gap; it cannot prove execution. P2/P3 have "
             "independent ingress corroboration. P0 detects nothing (no anchor).")
    L.append("- T4 retry/dup: two DISTINCT attempts plus one duplicate transmission. "
             "P0 merges the attempts (one bill for two executions = duplicate-metering "
             "error); P1-P3 key by attempt_id and keep them distinct.")
    L.append("- T5 observer failure: service executed and reported, but independent "
             "ingress evidence was lost. P2/P3 return UNCERTAIN; P0/P1 still say COVERED "
             "because their evidence stack contains no independent observation.")
    L.append("")
    L.append("## GO / NO-GO — evidence, not a pre-decided winner")
    L.append("")
    L.append("Facts that bear on each criterion (read the four-metric table above):")
    L.append("")
    L.append("- *Does the mandatory gateway (P1) already cover the target scenarios?* "
             "P1 detects the T3 evidence gap and rejects T2 bypass, but in T5 it still "
             "reports COVERED with no independent observation. Whether that residual is "
             "'worth researching' is a judgment; the data shows what P1 can and cannot see.")
    L.append("- *Does P2/P3 add a property beyond P1?* T5 is the discriminator: P2/P3 "
             "return UNCERTAIN where P1 reports COVERED; T3 adds independent ingress "
             "corroboration. This property comes with an explicit extra trust assumption "
             "(an independent observer), which must be weighed — not assumed away.")
    L.append("- *Is the extra property 'just another log'?* T2/T5 show the observer's "
             "evidence changes the verdict (bypass detection / uncertainty), not merely "
             "adds a row — but the observer independence is itself a trust assumption, "
             "so this is NOT claimed as a mechanism-only gain.")
    L.append("- *Could a simple access-control + signed-log + state check reproduce it?* "
             "P1 is essentially that baseline. The observed residual (T5) is exactly the "
             "question to decide; this experiment reports it, it does not resolve the "
             "architectural choice.")
    L.append("")
    L.append("Decision rule from the task package is applied only after independent review "
             "of these artifacts. P3 is NOT presumed strongest.")
    L.append("")
    L.append("## Prior art (do not re-package as novelty)")
    L.append("")
    for p in cfg["prior_art_baseline"]:
        L.append(f"- {p}")
    L.append("")
    L.append("## Residual boundaries")
    L.append("")
    L.append("- 50 trials validate reproducibility and scenario conformance, NOT statistical "
             "security; N=10 per scenario, fixed seeds.")
    L.append("- No real LLM/DeepSeek/MCP, no real TEE/remote attestation, no ZKP/Halo2, no "
             "cross-host consistency, no performance testing.")
    L.append("- This is a single-process logical prototype; independence is by separate "
             "DBs/keys, NOT hardware isolation or cross-organization trust.")
    L.append("- No exactly-once / global-truth claim; evidence coverage != execution truth.")
    REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    cfg = load_config()
    records = []
    for sc in SCENARIOS:
        for t in range(TRIALS):
            records.append(run_trial(sc, t).to_dict())

    with RAW.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    metrics = compute_metrics(records)
    conformance = expected_conformance(records)
    summary = {
        "experiment": "r2_4_phase2_gateway_coverage",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "seed_base": BASE_SEED,
        "trials_per_scenario": TRIALS,
        "total_records": len(records),
        "schemes": list(SCHEMES),
        "scenarios": list(SCENARIOS),
        "four_metrics": metrics,
        "expected_conformance": conformance,
        "gt_isolation": {
            "ground_truth_in_verifier_input": False,
            "enforced_by": ["verifier.py accepts ObservableEvidence only",
                            "assert_no_ground_truth in tests"],
        },
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                       encoding="utf-8")
    write_report(metrics, conformance, len(records), cfg)

    print(f"Wrote {len(records)} raw records -> {RAW.name}")
    print(f"Wrote {SUMMARY.name}, {REPORT.name}")
    for s in SCHEMES:
        c = metrics[s]["execution_coverage"]
        d = metrics[s]["missing_report_detection"]
        e = metrics[s]["duplicate_metering_error"]
        u = metrics[s]["uncertain_state_correctness"]
        print(f"  {s}: coverage={c['rate']} detect={d['rate']} "
              f"dup_err={e['errors']}/{e['trials']} uncertain={u['rate']}")


if __name__ == "__main__":
    main()
