"""H2.2 parameter-coverage supplement (run-002).

Frozen protocol docs/H2_EXPERIMENT_PROTOCOL.md §2 declares two scan grids that
run-001 did not complete:

  * C1 short TTL  tau in {5, 15, 60} s      -- run-001: tau=5 (M01-M05/M10/M11),
                                              tau=60 (M14 pathB); tau=15 MISSING.
  * C2 refresh R  R  in {5, 30, 120} s      -- run-001: R=30 only;
                                              R=5 and R=120 MISSING.

run-002 fills ONLY these missing arms. It does not modify any frozen H2.1
mechanism (h2_snapshot / h2_snapshot_state / h2_executor), nor the frozen
Runner / protocol / NO-GO criteria, and does NOT re-run any (scenario, group,
arm) unit already present in run-001. All new arms carry distinct arm labels.

Design of each added arm (kept identical in structure to the corresponding
run-001 unit so results are comparable):

  * M14 pathA (intermittent, refresh success), C2:
        bootstrap@0, revoke@10, exec@(10 + R), S=120.
        run-001 used R=30 -> exec@40, W_risk=30s.
        run-002 adds R=5  -> exec@15, and R=120 -> exec@130.
        This yields a W_risk-vs-R sequence {5s, 30s, 120s} from real
        injections, testing protocol §7.2 "W_risk decreases with R".
  * C1 tau=15 offline-window boundary:
        M02_offline_exec  exec@10 (<15) -> EXECUTED;
        M03_offline_expired exec@400 (>15) -> REJECTED (C_EXPIRED).
        tau is a C1 scan value; M14 head-to-head keeps its frozen A=60.

Outputs go to results/run-002/{trials.csv,summary.json,raw.json}. The work/
subdir is gitignored, same as run-001.

Honest scope note: in this single-execution-per-trial structure every C2
applicable trial performs at most one refresh attempt, so actual_refresh_request
_rate here measures 1 attempt per observation span for ALL R values and cannot
reveal the per-R sustained request cost. That cost dimension (protocol §6.4)
is deliberately NOT invented here; it remains an explicit boundary in the
report. No continuous-execution scenario is introduced because that would be a
new experiment design beyond this bounded supplement.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

# Importing run_experiment sets up the frozen sys.path (src / h2 / h1) and
# gives access to the frozen helpers. We only REUSE them; no frozen file is
# edited and no frozen class is modified in place.
from run_experiment import (  # noqa: E402
    Runner,
    _blank,
    _fill_result,
    write_outputs,
)
import run_experiment as _frozen  # noqa: E402

from h2_executor import OUTCOME_EXECUTED, OUTCOME_REJECTED, fresh_request  # noqa: E402

HERE = Path(__file__).resolve().parent

# Give every emitted row / summary the run-002 identity. This is a runtime
# constant override only; the frozen source file is untouched.
_frozen.RUN_ID = "run-002"

# The exact (scenario, group, arm) units completed by run-001. Used by the
# self-check to guarantee run-002 adds units only and never re-runs one.
RUN001_UNITS: set[tuple[str, str, str]] = {
    ("M14_head_to_head", "C2", "intermittent_pathA"),
    ("M14_head_to_head", "C1", "pure_offline_pathB"),
    ("M14_head_to_head", "C2", "pure_offline_pathB_expired"),
    ("M02_offline_exec", "C1", "base"),
    ("M03_offline_expired", "C1", "base"),
}


class ParamSweepRunner(Runner):
    """Runner subclass that executes only the missing parameter arms.

    Inherits emit() / _harness() / unit_observation / write_outputs-compatible
    state from the frozen Runner, so the R2.2 observation-span semantics and
    all NA rules are reused verbatim.
    """

    def m14_patha_r(self, idx: int, R: float) -> None:
        """M14 pathA, C2, one refresh interval R (S=120 fixed)."""
        h = self._harness(
            f"sweep-m14-pathA-R{R:g}-C2-{uuid.uuid4().hex}",
            validity=120.0,
            refresh=R,
        )
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()  # valid_until = 0 + 120
            jti, cred = h.authorize(ttl=300.0)
            h.clock.set(10.0)
            t_revoke = h.revoke(jti)
            # Same structure as run-001 pathA: exec one R after revocation.
            h.clock.set(10.0 + R)
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            row = _blank("M14_head_to_head", "C2", f"intermittent_pathA_R={R:g}", idx)
            row["jti"] = jti
            row["tau_s"] = "NA"
            row["snapshot_validity_s"] = 120.0
            row["refresh_interval_s"] = R
            r.t_revoke = t_revoke
            _fill_result(row, r)
            # Online refresh pulls a snapshot listing the jti -> REJECTED.
            self.emit(row, OUTCOME_REJECTED, path="A", R=R, reason=r.reason)
        finally:
            h.close()

    def m02_c1_tau15(self, idx: int) -> None:
        """C1 tau=15, offline but inside the short TTL -> EXECUTED."""
        h = self._harness(f"sweep-m02-C1-tau15-{uuid.uuid4().hex}")
        try:
            h.clock.set(0.0)
            jti, cred = h.authorize(ttl=15.0)
            h.b2_tls.shutdown()  # service offline
            h.clock.set(10.0)  # 10 < 15 -> credential still valid
            r = h.executor.execute_c_offline(
                group="C1", request=fresh_request(), credential=cred
            )
            row = _blank("M02_offline_exec", "C1", "tau=15", idx)
            row["jti"] = jti
            row["ttl_s"] = 15.0
            row["tau_s"] = 15.0
            row["service_online"] = "FALSE"
            _fill_result(row, r)
            self.emit(row, OUTCOME_EXECUTED, tau=15.0, note="C1 tau=15 inside offline window")
        finally:
            h.close()

    def m03_c1_tau15(self, idx: int) -> None:
        """C1 tau=15, offline beyond the short TTL -> REJECTED (C_EXPIRED)."""
        h = self._harness(f"sweep-m03-C1-tau15-{uuid.uuid4().hex}")
        try:
            h.clock.set(0.0)
            jti, cred = h.authorize(ttl=15.0)
            h.b2_tls.shutdown()  # service offline
            h.clock.set(400.0)  # 400 > 15 -> expired
            r = h.executor.execute_c_offline(
                group="C1", request=fresh_request(), credential=cred
            )
            row = _blank("M03_offline_expired", "C1", "tau=15", idx)
            row["jti"] = jti
            row["ttl_s"] = 15.0
            row["tau_s"] = 15.0
            row["service_online"] = "FALSE"
            _fill_result(row, r)
            self.emit(row, OUTCOME_REJECTED, tau=15.0, note="C1 tau=15 past offline window")
        finally:
            h.close()

    def sweep(self) -> None:
        t0 = time.perf_counter()
        for idx in range(self.n):
            # C2 R grid: only the two values missing from run-001.
            self.m14_patha_r(idx, 5.0)
            self.m14_patha_r(idx, 120.0)
            # C1 tau grid: only the value missing from run-001.
            self.m02_c1_tau15(idx)
            self.m03_c1_tau15(idx)
        self.run_wall_seconds = time.perf_counter() - t0


def _enrich_summary(summary: dict[str, Any], n: int) -> dict[str, Any]:
    summary["run_id"] = "run-002"
    summary["experiment"] = "H2.2 parameter-coverage supplement (run-002)"
    summary["mode"] = "param-sweep-smoke" if n == 1 else "param-sweep"
    summary["supplement_of"] = "run-001"
    summary["does_not_rerun_run001_units"] = True
    summary["parameter_grid"] = {
        "C1_tau_s": {"run_001": [5, 60], "run_002_added": [15], "complete": [5, 15, 60]},
        "C2_R_s": {"run_001": [30], "run_002_added": [5, 120], "complete": [5, 30, 120]},
        "C2_S_s": 120,
        "A_s": 60,
        "n_per_cell": n,
    }
    summary["added_units"] = [
        "M14_head_to_head / C2 / intermittent_pathA_R=5",
        "M14_head_to_head / C2 / intermittent_pathA_R=120",
        "M02_offline_exec / C1 / tau=15",
        "M03_offline_expired / C1 / tau=15",
    ]
    summary["meta"]["synthetic_cost_note"] = (
        "single execution per trial => refresh_attempts<=1 for every R; "
        "actual_refresh_request_rate here is 1 attempt per observation span "
        "and does NOT measure sustained per-R request cost (no continuous-"
        "execution scenario introduced; that would be a new experiment design)"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--smoke", action="store_true", help="callability check, N=1")
    g.add_argument("--full", action="store_true", help="formal supplement, N=10")
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    if args.output_dir:
        outdir = Path(args.output_dir)
    elif args.smoke:
        outdir = Path(tempfile.mkdtemp(prefix="h2-sweep-smoke-"))
    else:
        outdir = HERE / "results" / "run-002"
    workdir = outdir / "work"
    workdir.mkdir(parents=True, exist_ok=True)

    n = 1 if args.smoke else 10
    runner = ParamSweepRunner(workdir=workdir, n=n)
    runner.sweep()

    # Self-check: every emitted unit must be NEW relative to run-001.
    seen = {
        (r["scenario_id"], r["group"], r["arm"]) for r in runner.rows
    }
    overlap = seen & RUN001_UNITS
    if overlap:
        raise SystemExit(f"refusing to re-run run-001 units: {sorted(overlap)}")

    write_outputs(outdir, runner, n)
    sp = outdir / "summary.json"
    summary = _enrich_summary(json.loads(sp.read_text(encoding="utf-8")), n)
    sp.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not summary["all_pass"]:
        print("WARNING: some trials failed assertions; see trials.csv", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
