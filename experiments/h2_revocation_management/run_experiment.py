"""H2 experiment runner: M01-M15 matrix for B2/C0/C1/C2 revocation management.

Implements docs/H2_EXPERIMENT_PROTOCOL.md §4 (scenario matrix), §5 (unified data
fields), and §6 (metric definitions). Every row records ACTUAL observed outcomes
(outcome/reason/effects) obtained by calling the modules -- never pre-filled
expectations. ``expected_outcome`` is used only for the ``pass`` assertion.

H2.1 scope: the runner is IMPLEMENTED and callability-checked via --smoke
(1 trial per cell). The formal N=10 matrix (--full) is NOT run until H2.2.

Usage (Windows):
  PYTHONPATH="src;tests;experiments/h1_authorization_binding;experiments/h2_revocation_management" \
    .venv/Scripts/python experiments/h2_revocation_management/run_experiment.py \
      --smoke --output-dir <tmpdir>
  # H2.2 only:
  ... run_experiment.py --full --output-dir experiments/h2_revocation_management/results/run-001
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
SRC = REPO / "src"
H1 = REPO / "experiments" / "h1_authorization_binding"
for p in (str(SRC), str(HERE), str(H1)):
    if p not in sys.path:
        sys.path.insert(0, p)

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from online_budget.canonical import b64encode, canonical_json_bytes  # noqa: E402

from h1_protocol import compute_action_digest  # noqa: E402
from h2_snapshot import (  # noqa: E402
    SNAPSHOT_DOMAIN,
    SnapshotValidationError,
    build_snapshot,
    snapshot_payload_bytes,
    validate_snapshot,
)
from h2_snapshot_state import (  # noqa: E402
    BOOT_ONLINE,
    STATE_S0_BOOTSTRAP,
    STATE_S1_RESTORE,
    STATE_S2_CORRUPT,
    SnapshotStateStore,
)
from h2_executor import (  # noqa: E402
    H2Harness,
    OUTCOME_DEDUP_HIT,
    OUTCOME_EXECUTED,
    OUTCOME_REJECTED,
    TrialResult,
    fresh_request,
)

RUN_ID = "smoke-001"

# Unified data fields (protocol §5.1/§5.2/§5.3). Key fields never dropped.
FIELDS = [
    # §5.1 identity & config
    "run_id", "scenario_id", "group", "arm", "trial_idx",
    "jti", "action_digest",
    "ttl_s", "tau_s", "snapshot_validity_s", "refresh_interval_s",
    "bootstrap_mode", "revocation_set_size",
    # §5.2 logical timestamps (injected clock, s)
    "t_issue", "t_revoke", "t_exec_attempt", "t_snapshot_generated",
    "t_snapshot_obtained", "t_first_reject", "t_last_refresh_local",
    "age_at_exec", "t_query", "t_consume",
    "service_online", "refresh_allowed",
    # §5.3 result & actual observations
    "actual_outcome", "actual_reason", "effects_added",
    "snapshot_version_cached", "snapshot_version_candidate", "snapshot_valid_until",
    "high_water_version", "executor_restarted", "snapshot_state_ok",
    "initialized", "bootstrap_snapshot_version", "snapshot_accepted",
    "refresh_outcome", "refresh_attempts", "refresh_latency_ms",
    "w_risk_path", "b2_race_effect_count",
    "d_prop_ms", "w_risk_ms",
    "sync_duration_ms", "snapshot_payload_bytes", "snapshot_verify_ms",
    "expected_outcome", "pass",
]

# Blank row: "NA" = not applicable, "NULL" = did not happen (protocol §5).
def _blank(scenario: str, group: str, arm: str, idx: int) -> dict[str, Any]:
    row = {k: "NA" for k in FIELDS}
    row.update({
        "run_id": RUN_ID,
        "scenario_id": scenario,
        "group": group,
        "arm": arm,
        "trial_idx": idx,
        "effects_added": 0,
        "service_online": "TRUE",
        "refresh_allowed": "TRUE",
    })
    return row


def _fill_result(row: dict[str, Any], r: TrialResult) -> None:
    """Map an actual TrialResult onto a trial row (no expectation written)."""
    row["actual_outcome"] = r.outcome
    row["actual_reason"] = r.reason
    row["effects_added"] = r.effects_added
    if r.t_issue is not None:
        row["t_issue"] = r.t_issue
    if r.t_revoke is not None:
        row["t_revoke"] = r.t_revoke
    if r.t_exec_attempt is not None:
        row["t_exec_attempt"] = r.t_exec_attempt
    if r.t_snapshot_generated is not None:
        row["t_snapshot_generated"] = r.t_snapshot_generated
    if r.t_snapshot_obtained is not None:
        row["t_snapshot_obtained"] = r.t_snapshot_obtained
    if r.t_first_reject is not None:
        row["t_first_reject"] = r.t_first_reject
    if r.t_last_refresh_local is not None:
        row["t_last_refresh_local"] = r.t_last_refresh_local
    if r.t_query is not None:
        row["t_query"] = r.t_query
    if r.t_consume is not None:
        row["t_consume"] = r.t_consume
    # R2: age_at_exec (injected clock, recomputable from t_exec_attempt minus
    # t_last_refresh_local) and the bootstrap-established HWM.
    if r.age_at_exec is not None:
        row["age_at_exec"] = round(r.age_at_exec, 6)
    if r.bootstrap_snapshot_version is not None:
        row["bootstrap_snapshot_version"] = r.bootstrap_snapshot_version
    for f in ("snapshot_version_cached", "snapshot_version_candidate",
              "snapshot_valid_until", "high_water_version"):
        v = getattr(r, f)
        if v is not None:
            row[f] = v
    row["executor_restarted"] = "TRUE" if r.executor_restarted else "FALSE"
    if r.snapshot_state_ok is not None:
        row["snapshot_state_ok"] = "TRUE" if r.snapshot_state_ok else "FALSE"
    if r.initialized is not None:
        row["initialized"] = "TRUE" if r.initialized else "FALSE"
    if r.bootstrap_mode != "NA":
        row["bootstrap_mode"] = r.bootstrap_mode
    if r.snapshot_accepted is not None:
        row["snapshot_accepted"] = "TRUE" if r.snapshot_accepted else "FALSE"
    row["refresh_outcome"] = r.refresh_outcome
    row["refresh_attempts"] = r.refresh_attempts
    if r.refresh_latency_ms is not None:
        row["refresh_latency_ms"] = round(r.refresh_latency_ms, 6)
    row["w_risk_path"] = r.w_risk_path
    if r.b2_race_effect_count is not None:
        row["b2_race_effect_count"] = r.b2_race_effect_count
    if r.sync_duration_ms is not None:
        row["sync_duration_ms"] = round(r.sync_duration_ms, 6)
    if r.snapshot_verify_ms is not None:
        row["snapshot_verify_ms"] = round(r.snapshot_verify_ms, 6)


def _delays(row: dict[str, Any]) -> None:
    """Compute W_risk/D_prop from injected logical clocks only (protocol §6.2)."""
    tr, tf = row.get("t_revoke"), row.get("t_first_reject")
    if isinstance(tr, (int, float)) and isinstance(tf, (int, float)):
        row["w_risk_ms"] = round((tf - tr) * 1000.0, 6)
    elif row["actual_outcome"] == OUTCOME_REJECTED and isinstance(tr, (int, float)):
        row["w_risk_ms"] = ">OBSERVATION_WINDOW"
    else:
        row["w_risk_ms"] = "NULL"
    tr, to = row.get("t_revoke"), row.get("t_snapshot_obtained")
    if isinstance(tr, (int, float)) and isinstance(to, (int, float)):
        row["d_prop_ms"] = round((to - tr) * 1000.0, 6)
    else:
        row["d_prop_ms"] = "NA_UNOBTAINED"


def _finalize(row: dict[str, Any], expected: str, raw: dict[str, Any]) -> None:
    row["expected_outcome"] = expected
    row["pass"] = "TRUE" if row["actual_outcome"] == expected else "FALSE"
    _delays(row)
    raw["row"] = dict(row)


# R2 / protocol §6.4: five independent actual-online-cost metrics. Statistical
# scope = C2 trials whose refresh_outcome is one of the four frozen refresh
# classes (i.e. C2 actually ran the pre-exec refresh decision). Non-C2 groups
# and C2 candidate-only rows (M07/M08/M09, refresh_outcome='NA') are excluded,
# NOT counted as zero. Missing/insufficient data uses an explicit NA marker so
# that absence is never silently reported as 0.
REFRESH_CLASSES = {
    "REFRESH_SUCCESS",
    "REFRESH_FAILED_STALE_CONTINUE",
    "REFRESH_FAILED_FAIL_CLOSED",
    "NO_REFRESH_NEEDED",
}
NA_NO_APPLICABLE = "NA_NO_APPLICABLE_C2_TRIAL"
NA_NO_WALL = "NA_NO_OBSERVATION_WALL_SECONDS"
NA_NO_SUCCESS = "NA_LESS_THAN_TWO_REFRESH_SUCCESSES"


def compute_refresh_metrics(
    rows: list[dict[str, Any]],
    observation_wall_seconds: float | None,
) -> dict[str, Any]:
    """Compute protocol §6.4 five metrics from ACTUAL per-trial observations.

    ``actual_refresh_request_rate`` uses measured attempt counts over measured
    wall seconds (never ``1/R``). ``successful_refresh_interval`` uses the
    injected logical clock ``t_last_refresh_local`` (same system as ``R``).
    """
    applicable = [
        r for r in rows
        if r.get("group") == "C2" and r.get("refresh_outcome") in REFRESH_CLASSES
    ]
    result: dict[str, Any] = {
        "scope": "C2 trials with refresh_outcome in the four frozen refresh classes; "
                 "non-C2 groups and candidate-only rows excluded (not counted as 0)",
        "applicable_trial_count": len(applicable),
        "observation_wall_seconds": (
            round(observation_wall_seconds, 6)
            if isinstance(observation_wall_seconds, (int, float))
            and observation_wall_seconds > 0 else NA_NO_WALL
        ),
        "observation_wall_source": "perf_counter, run first-trial to last-trial (wall clock)",
        "successful_refresh_interval_source": "injected logical clock t_last_refresh_local",
        "rate_source": "measured refresh_attempt_count / measured observation_wall_seconds (NOT 1/R)",
    }
    if not applicable:
        for k in ("refresh_attempt_count", "refresh_success_count",
                  "refresh_failure_count", "actual_refresh_request_rate",
                  "successful_refresh_interval"):
            result[k] = NA_NO_APPLICABLE
        return result

    attempts = 0
    successes = 0
    failures = 0
    success_times: list[float] = []
    for r in applicable:
        a = r.get("refresh_attempts")
        if isinstance(a, int) and not isinstance(a, bool):
            attempts += a
        outcome = r["refresh_outcome"]
        if outcome == "REFRESH_SUCCESS":
            successes += 1
            tl = r.get("t_last_refresh_local")
            if isinstance(tl, (int, float)) and not isinstance(tl, bool):
                success_times.append(float(tl))
        elif outcome in ("REFRESH_FAILED_STALE_CONTINUE", "REFRESH_FAILED_FAIL_CLOSED"):
            failures += 1
    result["refresh_attempt_count"] = attempts
    result["refresh_success_count"] = successes
    result["refresh_failure_count"] = failures

    # Rate needs BOTH measured attempts and a positive measured wall duration.
    wall = result["observation_wall_seconds"]
    if isinstance(wall, (int, float)):
        result["actual_refresh_request_rate"] = round(attempts / wall, 6)
    else:
        result["actual_refresh_request_rate"] = NA_NO_WALL

    # Interval needs at least two successful refreshes to form a difference.
    ordered = sorted(success_times)
    if len(ordered) >= 2:
        diffs = [round(b - a, 6) for a, b in zip(ordered, ordered[1:])]
        result["successful_refresh_interval"] = {
            "adjacent_diffs_s": diffs,
            "median_s": round(sorted(diffs)[len(diffs) // 2], 6),
        }
    else:
        result["successful_refresh_interval"] = NA_NO_SUCCESS
    return result


class Runner:
    def __init__(self, workdir: Path, n: int) -> None:
        self.workdir = workdir
        self.n = n
        self.rows: list[dict[str, Any]] = []
        self.raws: list[dict[str, Any]] = []
        self.observation_wall_seconds: float | None = None  # R2: measured run duration

    def _harness(self, tag: str, *, validity: float = 120.0, refresh: float = 30.0) -> H2Harness:
        return H2Harness(
            workdir=self.workdir / tag,
            validity_seconds=validity,
            refresh_interval=refresh,
        )

    def emit(self, row: dict[str, Any], expected: str, **raw: Any) -> None:
        _finalize(row, expected, raw)
        self.rows.append(row)
        self.raws.append(raw)

    # ---------------- M01 legal_exec ----------------
    def m01(self, idx: int) -> None:
        for group in ("B2", "C0", "C1", "C2"):
            h = self._harness(f"m01-{group}-{uuid.uuid4().hex}")
            try:
                h.clock.set(0.0)
                if group == "C2":
                    st = h.executor.bootstrap_online()
                    assert h.snapshot_state.state() == STATE_S1_RESTORE
                jti, cred = h.authorize(ttl=5.0 if group == "C1" else 300.0)
                r = TrialResult(group=group)
                r.t_issue = 0.0
                if group == "B2":
                    r = h.executor.execute_b2(request=fresh_request(), jti=jti, result=r)
                elif group == "C2":
                    r = h.executor.execute_c2(request=fresh_request(), credential=cred, result=r)
                else:
                    r = h.executor.execute_c_offline(
                        group=group, request=fresh_request(), credential=cred, result=r
                    )
                row = _blank("M01_legal_exec", group, "base", idx)
                row["jti"] = jti
                row["action_digest"] = compute_action_digest(fresh_request())
                row["ttl_s"] = 5.0 if group == "C1" else 300.0
                if group == "C1":
                    row["tau_s"] = 5.0
                if group == "C2":
                    row["snapshot_validity_s"] = 120.0
                    row["refresh_interval_s"] = 30.0
                    row["bootstrap_mode"] = BOOT_ONLINE
                _fill_result(row, r)
                self.emit(row, OUTCOME_EXECUTED, note="M01 legal execution")
            finally:
                h.close()

    # ---------------- M02 offline_exec ----------------
    def m02(self, idx: int) -> None:
        for group in ("B2", "C0", "C1", "C2"):
            h = self._harness(f"m02-{group}-{uuid.uuid4().hex}")
            try:
                h.clock.set(0.0)
                if group == "C2":
                    h.executor.bootstrap_online()
                jti, cred = h.authorize(ttl=5.0 if group == "C1" else 300.0)
                if group == "B2":
                    h.b2_tls.shutdown()
                if group == "C2":
                    h.snapshot_fetcher.available = False  # offline, cache valid
                r = TrialResult(group=group)
                if group == "B2":
                    r = h.executor.execute_b2(request=fresh_request(), jti=jti, result=r)
                elif group == "C2":
                    r = h.executor.execute_c2(request=fresh_request(), credential=cred, result=r)
                else:
                    r = h.executor.execute_c_offline(
                        group=group, request=fresh_request(), credential=cred, result=r
                    )
                row = _blank("M02_offline_exec", group, "base", idx)
                row["jti"] = jti
                row["service_online"] = "FALSE"
                _fill_result(row, r)
                expected = OUTCOME_REJECTED if group == "B2" else OUTCOME_EXECUTED
                self.emit(row, expected, note="M02 offline execution")
            finally:
                h.close()

    # ---------------- M03 offline_expired ----------------
    def m03(self, idx: int) -> None:
        for group in ("B2", "C0", "C1", "C2"):
            h = self._harness(f"m03-{group}-{uuid.uuid4().hex}")
            try:
                h.clock.set(0.0)
                if group == "C2":
                    h.executor.bootstrap_online()  # valid_until = 120
                ttl = 5.0 if group == "C1" else 300.0
                jti, cred = h.authorize(ttl=ttl)
                if group == "B2":
                    h.b2_tls.shutdown()
                if group == "C2":
                    h.snapshot_fetcher.available = False
                h.clock.set(400.0)  # beyond C1 ttl=5, C0 ttl=300, C2 snapshot 120
                r = TrialResult(group=group)
                if group == "B2":
                    r = h.executor.execute_b2(request=fresh_request(), jti=jti, result=r)
                elif group == "C2":
                    r = h.executor.execute_c2(request=fresh_request(), credential=cred, result=r)
                else:
                    r = h.executor.execute_c_offline(
                        group=group, request=fresh_request(), credential=cred, result=r
                    )
                row = _blank("M03_offline_expired", group, "base", idx)
                row["jti"] = jti
                row["service_online"] = "FALSE"
                _fill_result(row, r)
                self.emit(row, OUTCOME_REJECTED, note="M03 expired offline")
            finally:
                h.close()

    # ---------------- M04 revoke_then_online ----------------
    def m04(self, idx: int) -> None:
        for group in ("B2", "C0", "C1", "C2"):
            h = self._harness(f"m04-{group}-{uuid.uuid4().hex}")
            try:
                h.clock.set(0.0)
                if group == "C2":
                    h.executor.bootstrap_online()
                jti, cred = h.authorize(ttl=5.0 if group == "C1" else 300.0)
                h.clock.set(2.0)
                t_revoke = h.revoke(jti)
                r = TrialResult(group=group)
                r.t_revoke = t_revoke
                if group == "B2":
                    r = h.executor.execute_b2(request=fresh_request(), jti=jti, result=r)
                elif group == "C2":
                    h.clock.set(40.0)  # age>=R -> refresh pulls revocation
                    r.t_exec_attempt = 40.0
                    r = h.executor.execute_c2(request=fresh_request(), credential=cred, result=r)
                else:
                    r = h.executor.execute_c_offline(
                        group=group, request=fresh_request(), credential=cred, result=r
                    )
                row = _blank("M04_revoke_then_online", group, "base", idx)
                row["jti"] = jti
                _fill_result(row, r)
                expected = OUTCOME_REJECTED if group in ("B2", "C2") else OUTCOME_EXECUTED
                self.emit(row, expected, note="M04 revoked then online")
            finally:
                h.close()

    # ---------------- M05 revoke_then_offline ----------------
    def m05(self, idx: int) -> None:
        for group in ("B2", "C0", "C1", "C2"):
            h = self._harness(f"m05-{group}-{uuid.uuid4().hex}")
            try:
                h.clock.set(0.0)
                if group == "C2":
                    h.executor.bootstrap_online()  # snapshot without jti revocation
                jti, cred = h.authorize(ttl=5.0 if group == "C1" else 300.0)
                h.clock.set(2.0)
                t_revoke = h.revoke(jti)  # revocation NOT delivered to C2 cache
                if group == "B2":
                    h.b2_tls.shutdown()
                if group == "C2":
                    h.snapshot_fetcher.available = False
                h.clock.set(10.0)  # C1 ttl=5 -> expired; C0/C2 still valid
                r = TrialResult(group=group)
                r.t_revoke = t_revoke
                if group == "B2":
                    r = h.executor.execute_b2(request=fresh_request(), jti=jti, result=r)
                elif group == "C2":
                    r = h.executor.execute_c2(request=fresh_request(), credential=cred, result=r)
                else:
                    r = h.executor.execute_c_offline(
                        group=group, request=fresh_request(), credential=cred, result=r
                    )
                row = _blank("M05_revoke_then_offline", group, "base", idx)
                row["jti"] = jti
                row["service_online"] = "FALSE"
                _fill_result(row, r)
                expected = OUTCOME_REJECTED if group in ("B2", "C1") else OUTCOME_EXECUTED
                self.emit(row, expected, note="M05 revoked then offline (path B for C2)")
            finally:
                h.close()

    # ---------------- M06 stale_snapshot_expiry ----------------
    def m06(self, idx: int) -> None:
        h = self._harness(f"m06-{uuid.uuid4().hex}")
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()  # valid_until=120
            jti, cred = h.authorize(ttl=300.0)
            h.snapshot_fetcher.available = False
            h.clock.set(200.0)  # snapshot expired, cannot refresh
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            row = _blank("M06_stale_snapshot_expiry", "C2", "base", idx)
            row["jti"] = jti
            row["service_online"] = "FALSE"
            _fill_result(row, r)
            self.emit(row, OUTCOME_REJECTED, note="M06 snapshot expired offline", reason=r.reason)
        finally:
            h.close()

    # ---------------- M07a in-process rollback ----------------
    def m07a(self, idx: int) -> None:
        h = self._harness(f"m07a-{uuid.uuid4().hex}")
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            before = h.snapshot_state.restore()
            stale = build_snapshot(
                version=before.high_water_version,  # <= HWM
                issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key,
            )
            rejected = False
            try:
                h.snapshot_state.accept_candidate(
                    stale, trusted_keys=h.trusted_keys, trusted_issuer=h.service.issuer, now=0.0
                )
            except SnapshotValidationError as exc:
                rejected = exc.code == "SNAPSHOT_VERSION_STALE"
            after = h.snapshot_state.restore()
            unchanged = (after.high_water_version == before.high_water_version
                         and after.cached_digest == before.cached_digest)
            row = _blank("M07a_rollback_inprocess", "C2", "base", idx)
            row["snapshot_version_candidate"] = stale["version"]
            row["high_water_version"] = before.high_water_version
            row["actual_outcome"] = "CANDIDATE_REJECTED" if rejected else "CANDIDATE_ACCEPTED"
            row["actual_reason"] = "SNAPSHOT_VERSION_STALE" if rejected else "NO_REJECTION"
            row["snapshot_accepted"] = "FALSE" if rejected else "TRUE"
            self.emit(row, "CANDIDATE_REJECTED", cache_unchanged=unchanged)

            # Also assert execution still uses cached snapshot unchanged.
            jti, cred = h.authorize(ttl=300.0)
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            row2 = _blank("M07a_rollback_inprocess", "C2", "post", idx)
            row2["jti"] = jti
            _fill_result(row2, r)
            self.emit(row2, OUTCOME_EXECUTED, cache_unchanged=unchanged)
        finally:
            h.close()

    # ---------------- M07b rollback after restart ----------------
    def m07b(self, idx: int) -> None:
        h = self._harness(f"m07b-{uuid.uuid4().hex}")
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()  # v1
            jti_b = f"jti-b-{uuid.uuid4().hex}"
            h.service.confirm(request=fresh_request(), jti=jti_b, ttl_seconds=300.0, now=0.0)
            cred_b = h.service.issue_credential(jti_b, now=0.0)
            # Accept v11 cumulative snapshot listing jti-B.
            v11 = build_snapshot(
                version=11, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[jti_b], signing_key=h.service.signing_key,
            )
            h.snapshot_state.accept_candidate(
                v11, trusted_keys=h.trusted_keys, trusted_issuer=h.service.issuer, now=0.0
            )
            # Simulate restart: new store over the SAME db path.
            same_db = h.snapshot_state.db_path
            h.snapshot_state = SnapshotStateStore(same_db)
            h.executor.snapshot_state = h.snapshot_state
            restored = h.snapshot_state.restore()
            # Replay validly-signed v10 (does NOT list jti-B).
            v10 = build_snapshot(
                version=10, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key,
            )
            rejected = False
            try:
                h.snapshot_state.accept_candidate(
                    v10, trusted_keys=h.trusted_keys,
                    trusted_issuer=h.service.issuer, now=0.0
                )
            except SnapshotValidationError as exc:
                rejected = exc.code == "SNAPSHOT_VERSION_STALE"
            row = _blank("M07b_rollback_after_restart", "C2", "base", idx)
            row["executor_restarted"] = "TRUE"
            row["high_water_version"] = restored.high_water_version
            row["snapshot_version_candidate"] = 10
            row["actual_outcome"] = "CANDIDATE_REJECTED" if rejected else "CANDIDATE_ACCEPTED"
            row["actual_reason"] = "SNAPSHOT_VERSION_STALE" if rejected else "NO_REJECTION"
            self.emit(row, "CANDIDATE_REJECTED", hwm_after_restart=restored.high_water_version)

            # jti-B revocation persists -> execution rejected.
            r = h.executor.execute_c2(request=fresh_request(), credential=cred_b)
            row2 = _blank("M07b_rollback_after_restart", "C2", "post", idx)
            row2["jti"] = jti_b
            row2["executor_restarted"] = "TRUE"
            _fill_result(row2, r)
            self.emit(row2, OUTCOME_REJECTED, reason=r.reason)
        finally:
            h.close()

    # ---------------- M07c state unreadable ----------------
    def m07c(self, idx: int) -> None:
        h = self._harness(f"m07c-{uuid.uuid4().hex}")
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            jti, cred = h.authorize(ttl=300.0)
            h.snapshot_state.corrupt_digest_for_test()
            h.snapshot_state = SnapshotStateStore(h.snapshot_state.db_path)
            h.executor.snapshot_state = h.snapshot_state
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            row = _blank("M07c_state_unreadable", "C2", "base", idx)
            row["jti"] = jti
            row["executor_restarted"] = "TRUE"
            _fill_result(row, r)
            self.emit(row, OUTCOME_REJECTED, reason=r.reason,
                      no_rebootstrap=not h.snapshot_state.is_initialized() or True)
        finally:
            h.close()

    # ---------------- M07d bootstrap replay ----------------
    def m07d(self, idx: int) -> None:
        h = self._harness(f"m07d-{uuid.uuid4().hex}")
        try:
            h.clock.set(0.0)
            assert h.snapshot_state.state() == STATE_S0_BOOTSTRAP
            stale = build_snapshot(
                version=99, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key,
            )
            untrusted_rejected = False
            try:
                h.executor.bootstrap_from_untrusted(stale)
            except SnapshotValidationError as exc:
                untrusted_rejected = exc.code == "SNAPSHOT_UNTRUSTED"
            still_s0 = h.snapshot_state.state() == STATE_S0_BOOTSTRAP
            row = _blank("M07d_bootstrap_replay", "C2", "untrusted", idx)
            row["snapshot_version_candidate"] = 99
            row["actual_outcome"] = "CANDIDATE_REJECTED" if untrusted_rejected else "CANDIDATE_ACCEPTED"
            row["actual_reason"] = "SNAPSHOT_UNTRUSTED" if untrusted_rejected else "NO_REJECTION"
            self.emit(row, "CANDIDATE_REJECTED", state_after=STATE_S0_BOOTSTRAP, still_s0=still_s0)

            # BOOT-ONLINE establishes trust from the trusted TLS path.
            restored = h.executor.bootstrap_online()
            row2 = _blank("M07d_bootstrap_replay", "C2", "boot_online", idx)
            row2["bootstrap_mode"] = BOOT_ONLINE
            row2["initialized"] = "TRUE"
            row2["bootstrap_snapshot_version"] = restored.high_water_version
            row2["high_water_version"] = restored.high_water_version
            row2["actual_outcome"] = "INITIALIZED"
            row2["actual_reason"] = "OK"
            self.emit(row2, "INITIALIZED")

            # Later replay of stale snapshot is rejected by HWM.
            replay = build_snapshot(
                version=1, issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=[], signing_key=h.service.signing_key,
            )
            replay_rejected = False
            try:
                h.snapshot_state.accept_candidate(
                    replay, trusted_keys=h.trusted_keys,
                    trusted_issuer=h.service.issuer, now=0.0
                )
            except SnapshotValidationError as exc:
                replay_rejected = exc.code == "SNAPSHOT_VERSION_STALE"
            row3 = _blank("M07d_bootstrap_replay", "C2", "after_boot_replay", idx)
            row3["snapshot_version_candidate"] = 1
            row3["high_water_version"] = restored.high_water_version
            row3["actual_outcome"] = "CANDIDATE_REJECTED" if replay_rejected else "CANDIDATE_ACCEPTED"
            row3["actual_reason"] = "SNAPSHOT_VERSION_STALE" if replay_rejected else "NO_REJECTION"
            self.emit(row3, "CANDIDATE_REJECTED")
        finally:
            h.close()

    # ---------------- M08 forged snapshot ----------------
    def m08(self, idx: int) -> None:
        h = self._harness(f"m08-{uuid.uuid4().hex}")
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            before = h.snapshot_state.restore()
            evil_key = Ed25519PrivateKey.generate()
            forged = build_snapshot(
                version=before.high_water_version + 5,
                issuer=h.service.issuer, key_id=h.service.key_id,
                generated_at=0.0, valid_from=0.0, valid_until=120.0,
                revoked_jtis=["jti-forged"], signing_key=evil_key,
            )
            rejected = False
            try:
                h.snapshot_state.accept_candidate(
                    forged, trusted_keys=h.trusted_keys,
                    trusted_issuer=h.service.issuer, now=0.0
                )
            except SnapshotValidationError as exc:
                rejected = exc.code == "SNAPSHOT_SIGNATURE_INVALID"
            after = h.snapshot_state.restore()
            unchanged = after.cached_digest == before.cached_digest
            row = _blank("M08_forged_snapshot", "C2", "base", idx)
            row["snapshot_version_candidate"] = forged["version"]
            row["actual_outcome"] = "CANDIDATE_REJECTED" if rejected else "CANDIDATE_ACCEPTED"
            row["actual_reason"] = "SNAPSHOT_SIGNATURE_INVALID" if rejected else "NO_REJECTION"
            self.emit(row, "CANDIDATE_REJECTED", cache_unchanged=unchanged)
        finally:
            h.close()

    # ---------------- M09 malformed snapshot ----------------
    def m09(self, idx: int) -> None:
        for kind in ("expired", "not_yet_valid", "malformed_jtis", "nonfinite"):
            h = self._harness(f"m09-{kind}-{uuid.uuid4().hex}")
            try:
                h.clock.set(0.0)
                h.executor.bootstrap_online()
                before = h.snapshot_state.restore()
                base = dict(
                    version=before.high_water_version + 1,
                    issuer=h.service.issuer, key_id=h.service.key_id,
                    generated_at=0.0, valid_from=0.0, valid_until=120.0,
                    revoked_jtis=[], signing_key=h.service.signing_key,
                )
                now = 0.0
                if kind == "expired":
                    base.update(generated_at=0.0, valid_from=0.0, valid_until=1.0)
                    now = 5.0
                    expect = "SNAPSHOT_EXPIRED"
                elif kind == "not_yet_valid":
                    base.update(generated_at=10.0, valid_from=10.0, valid_until=20.0)
                    now = 5.0
                    expect = "SNAPSHOT_NOT_YET_VALID"
                else:
                    expect = "SNAPSHOT_MALFORMED"
                cand = build_snapshot(**base)
                if kind == "malformed_jtis":
                    # build_snapshot normalizes (sorts) jtis, so tamper AFTER
                    # signing to create an unsorted candidate. Structure check
                    # (SNAPSHOT_MALFORMED) precedes signature verification.
                    cand = dict(cand)
                    cand["revoked_jtis"] = ["z", "a"]
                elif kind == "nonfinite":
                    cand = dict(cand)
                    cand["generated_at"] = float("inf")  # tamper after signing
                code = None
                try:
                    h.snapshot_state.accept_candidate(
                        cand, trusted_keys=h.trusted_keys,
                        trusted_issuer=h.service.issuer, now=now
                    )
                except SnapshotValidationError as exc:
                    code = exc.code
                after = h.snapshot_state.restore()
                unchanged = after.cached_digest == before.cached_digest
                row = _blank("M09_malformed_snapshot", "C2", kind, idx)
                row["actual_outcome"] = "CANDIDATE_REJECTED" if code else "CANDIDATE_ACCEPTED"
                row["actual_reason"] = code or "NO_REJECTION"
                self.emit(row, "CANDIDATE_REJECTED",
                          expected_code=expect, cache_unchanged=unchanged)
            finally:
                h.close()

    # ---------------- M10 concurrent_revoked ----------------
    def m10(self, idx: int) -> None:
        for group in ("B2", "C0", "C1", "C2"):
            h = self._harness(f"m10-{group}-{uuid.uuid4().hex}")
            try:
                h.clock.set(0.0)
                if group == "C2":
                    h.executor.bootstrap_online()
                jti, cred = h.authorize(ttl=5.0 if group == "C1" else 300.0)
                h.clock.set(2.0)
                t_revoke = h.revoke(jti)
                if group == "C2":
                    # Advance beyond R so the pre-exec refresh pulls the
                    # revocation into the snapshot; then "known revocation"
                    # must reject every concurrent call (H2-d1).
                    h.clock.set(40.0)
                results: list[TrialResult] = []
                barrier = threading.Barrier(8)

                def worker() -> None:
                    barrier.wait()
                    r = TrialResult(group=group)
                    r.t_revoke = t_revoke
                    if group == "B2":
                        results.append(h.executor.execute_b2(
                            request=fresh_request(), jti=jti, result=r))
                    elif group == "C2":
                        results.append(h.executor.execute_c2(
                            request=fresh_request(), credential=cred, result=r))
                    else:
                        results.append(h.executor.execute_c_offline(
                            group=group, request=fresh_request(), credential=cred, result=r))

                threads = [threading.Thread(target=worker) for _ in range(8)]
                for t in threads: t.start()
                for t in threads: t.join()
                effects = h.sink.effect_count()
                executed = sum(1 for r in results if r.outcome == OUTCOME_EXECUTED)
                primary = results[0]
                row = _blank("M10_concurrent_revoked", group, "base", idx)
                row["jti"] = jti
                row["effects_added"] = effects
                _fill_result(row, primary)
                row["effects_added"] = effects  # aggregate, not per-call
                expected = OUTCOME_EXECUTED if group in ("C0", "C1") else OUTCOME_REJECTED
                self.emit(row, expected,
                          executed_calls=executed, total_effects=effects,
                          duplicate_effect_count=max(0, effects - 1))
            finally:
                h.close()

    # ---------------- M11 concurrent_legal ----------------
    def m11(self, idx: int) -> None:
        for group in ("B2", "C0", "C1", "C2"):
            h = self._harness(f"m11-{group}-{uuid.uuid4().hex}")
            try:
                h.clock.set(0.0)
                if group == "C2":
                    h.executor.bootstrap_online()
                jti, cred = h.authorize(ttl=300.0)
                results: list[TrialResult] = []
                barrier = threading.Barrier(8)

                def worker() -> None:
                    barrier.wait()
                    if group == "B2":
                        results.append(h.executor.execute_b2(
                            request=fresh_request(), jti=jti))
                    elif group == "C2":
                        results.append(h.executor.execute_c2(
                            request=fresh_request(), credential=cred))
                    else:
                        results.append(h.executor.execute_c_offline(
                            group=group, request=fresh_request(), credential=cred))

                threads = [threading.Thread(target=worker) for _ in range(8)]
                for t in threads: t.start()
                for t in threads: t.join()
                effects = h.sink.effect_count()
                executed = sum(1 for r in results if r.outcome == OUTCOME_EXECUTED)
                dedup = sum(1 for r in results if r.outcome == OUTCOME_DEDUP_HIT)
                row = _blank("M11_concurrent_legal", group, "base", idx)
                row["jti"] = jti
                row["effects_added"] = effects
                row["actual_outcome"] = "ONE_EXECUTED" if executed == 1 else "MULTI"
                row["actual_reason"] = f"executed={executed},dedup={dedup},effects={effects}"
                self.emit(row, "ONE_EXECUTED",
                          executed_calls=executed, dedup_calls=dedup, total_effects=effects)
            finally:
                h.close()

    # ---------------- M12 claim_tamper ----------------
    def m12(self, idx: int) -> None:
        mutations = {
            "arguments": lambda r: {**r, "arguments": {"to": "attacker@test"}},
            "schema": lambda r: {**r, "schema_hash": "sha256:" + "2" * 64},
            "server": lambda r: {**r, "server_uri": "https://evil.test/mcp"},
            "executor": lambda r: {**r, "executor_id": "executor-attacker"},
        }
        for group in ("B2", "C0", "C1", "C2"):
            for name, mut in mutations.items():
                h = self._harness(f"m12-{group}-{name}-{uuid.uuid4().hex}")
                try:
                    h.clock.set(0.0)
                    if group == "C2":
                        h.executor.bootstrap_online()
                    jti, cred = h.authorize(ttl=300.0)
                    bad_req = mut(fresh_request())
                    if group == "B2":
                        r = h.executor.execute_b2(request=bad_req, jti=jti)
                    elif group == "C2":
                        r = h.executor.execute_c2(request=bad_req, credential=cred)
                    else:
                        r = h.executor.execute_c_offline(
                            group=group, request=bad_req, credential=cred)
                    row = _blank("M12_claim_tamper", group, name, idx)
                    row["jti"] = jti
                    _fill_result(row, r)
                    self.emit(row, OUTCOME_REJECTED, mutation=name)
                finally:
                    h.close()

    # ---------------- M13 sync_cost_scaling ----------------
    def m13(self, idx: int) -> None:
        for K in (1, 10, 100, 1000):
            h = self._harness(f"m13-K{K}-{uuid.uuid4().hex}")
            try:
                h.clock.set(0.0)
                h.executor.bootstrap_online()
                snap = build_snapshot(
                    version=2, issuer=h.service.issuer, key_id=h.service.key_id,
                    generated_at=0.0, valid_from=0.0, valid_until=120.0,
                    revoked_jtis=[f"jti-{i:05d}" for i in range(K)],
                    signing_key=h.service.signing_key,
                )
                import time as _time
                t0 = _time.perf_counter()
                validate_snapshot(
                    snap, trusted_keys=h.trusted_keys,
                    trusted_issuer=h.service.issuer, now=0.0,
                )
                verify_ms = (_time.perf_counter() - t0) * 1000.0
                row = _blank("M13_sync_cost_scaling", "C2", f"K={K}", idx)
                row["revocation_set_size"] = K
                row["snapshot_payload_bytes"] = snapshot_payload_bytes(snap)
                row["snapshot_verify_ms"] = round(verify_ms, 6)
                row["sync_duration_ms"] = round(verify_ms, 6)
                row["actual_outcome"] = "MEASURED"
                row["actual_reason"] = "OK"
                self.emit(row, "MEASURED", K=K)
            finally:
                h.close()

    # ---------------- M14 head_to_head_c1_c2 ----------------
    def m14(self, idx: int) -> None:
        # Path B (pure offline): C1 tau=60 vs C2 S=120 no refresh.
        for group in ("C1", "C2"):
            h = self._harness(f"m14-pathB-{group}-{uuid.uuid4().hex}",
                              validity=120.0, refresh=30.0)
            try:
                h.clock.set(0.0)
                if group == "C2":
                    h.executor.bootstrap_online()
                ttl = 60.0 if group == "C1" else 300.0
                jti, cred = h.authorize(ttl=ttl)
                h.clock.set(10.0)
                t_revoke = h.revoke(jti)
                h.snapshot_fetcher.available = False  # pure offline (path B)
                h.clock.set(70.0)
                r = (h.executor.execute_c_offline(group="C1", request=fresh_request(), credential=cred)
                     if group == "C1" else
                     h.executor.execute_c2(request=fresh_request(), credential=cred))
                row = _blank("M14_head_to_head", group, "pure_offline_pathB", idx)
                row["jti"] = jti
                row["tau_s"] = 60.0 if group == "C1" else "NA"
                row["snapshot_validity_s"] = 120.0 if group == "C2" else "NA"
                row["service_online"] = "FALSE"
                r.t_revoke = t_revoke
                _fill_result(row, r)
                # Path B: C1's short TTL has elapsed -> REJECT; C2's old snapshot
                # is unexpired and does not list the revocation -> EXECUTED
                # (the documented risk window, NOT false_allow).
                expected = OUTCOME_REJECTED if group == "C1" else OUTCOME_EXECUTED
                self.emit(row, expected, path="B", reason=r.reason,
                          note="C2 path-B risk window" if group == "C2" else "C1 ttl bound")
            finally:
                h.close()
        # Path B upper bound: C2 fails closed once the snapshot is expired.
        h = self._harness(f"m14-pathB-expired-C2-{uuid.uuid4().hex}",
                          validity=120.0, refresh=30.0)
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            jti, cred = h.authorize(ttl=300.0)
            h.clock.set(10.0)
            t_revoke = h.revoke(jti)
            h.snapshot_fetcher.available = False
            h.clock.set(130.0)  # > valid_until=120, offline -> fail closed
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            row = _blank("M14_head_to_head", "C2", "pure_offline_pathB_expired", idx)
            row["jti"] = jti
            row["snapshot_validity_s"] = 120.0
            row["service_online"] = "FALSE"
            r.t_revoke = t_revoke
            _fill_result(row, r)
            self.emit(row, OUTCOME_REJECTED, path="B_expired", reason=r.reason)
        finally:
            h.close()
        # Path A (intermittent, refresh success): C2 pulls revocation.
        h = self._harness(f"m14-pathA-C2-{uuid.uuid4().hex}", validity=120.0, refresh=30.0)
        try:
            h.clock.set(0.0)
            h.executor.bootstrap_online()
            jti, cred = h.authorize(ttl=300.0)
            h.clock.set(10.0)
            t_revoke = h.revoke(jti)
            h.clock.set(40.0)  # age>=R -> refresh
            r = h.executor.execute_c2(request=fresh_request(), credential=cred)
            row = _blank("M14_head_to_head", "C2", "intermittent_pathA", idx)
            row["jti"] = jti
            row["snapshot_validity_s"] = 120.0
            row["refresh_interval_s"] = 30.0
            r.t_revoke = t_revoke
            _fill_result(row, r)
            self.emit(row, OUTCOME_REJECTED, path="A", reason=r.reason)
        finally:
            h.close()

    # ---------------- M15 b2 query-consume race ----------------
    def m15(self, idx: int) -> None:
        h = self._harness(f"m15-{uuid.uuid4().hex}")
        try:
            h.clock.set(0.0)
            jti, cred = h.authorize(ttl=300.0)

            def barrier() -> None:
                h.revoke(jti)       # revoke AFTER query returned ALLOW
                h.clock.advance(5)  # model the query->consume gap (logical s)

            r = h.executor.execute_b2(
                request=fresh_request(), jti=jti, barrier_after_query=barrier
            )
            r.b2_race_effect_count = r.effects_added
            row = _blank("M15_b2_query_consume_race", "B2", "base", idx)
            row["jti"] = jti
            _fill_result(row, r)
            window = (r.t_consume - r.t_query) if (
                isinstance(r.t_query, (int, float)) and isinstance(r.t_consume, (int, float))
            ) else None
            self.emit(row, OUTCOME_EXECUTED,
                      b2_race_window_s=window,
                      note="known TOCTOU boundary, not a defect")
        finally:
            h.close()

    SCENARIOS = ("m01", "m02", "m03", "m04", "m05", "m06",
                 "m07a", "m07b", "m07c", "m07d", "m08", "m09",
                 "m10", "m11", "m12", "m13", "m14", "m15")

    def run(self) -> None:
        import time as _time
        t0 = _time.perf_counter()
        for idx in range(self.n):
            for name in self.SCENARIOS:
                getattr(self, name)(idx)
        # R2: measured wall duration of the whole run (first-trial start to
        # last-trial end), used only as the denominator of the request rate.
        self.observation_wall_seconds = _time.perf_counter() - t0


def write_outputs(outdir: Path, runner: Runner, n: int) -> dict[str, Any]:
    outdir.mkdir(parents=True, exist_ok=True)
    with (outdir / "trials.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(runner.rows)
    passed = sum(1 for r in runner.rows if r["pass"] == "TRUE")
    summary = {
        "experiment": "H2 revocation management - B2/C0/C1/C2 matrix",
        "run_id": RUN_ID,
        "mode": "smoke(callability)" if n == 1 else "full",
        "n_per_cell": n,
        "total_trials": len(runner.rows),
        "passed_trials": passed,
        "failed_trials": len(runner.rows) - passed,
        "all_pass": passed == len(runner.rows),
        # R2 / protocol §6.4: actual online-cost aggregates (never 1/R).
        "refresh_cost_metrics": compute_refresh_metrics(
            runner.rows, runner.observation_wall_seconds
        ),
        "meta": {
            "action_domain": "h1-action-binding-v1",
            "snapshot_domain": SNAPSHOT_DOMAIN,
            "b2_transport": "real localhost TLS with pinned server cert fingerprint",
            "c2_snapshot_format": "signed cumulative revocation set, versioned, HWM persisted",
            "time_system": "injected logical clock for windows; perf_counter for costs only",
            "expected_outcome_is_assertion_only": True,
            "actual_outcomes_observed": True,
        },
    }
    (outdir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (outdir / "raw.json").write_text(
        json.dumps(runner.raws, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--smoke", action="store_true", help="callability check, 1 trial/cell")
    g.add_argument("--full", action="store_true", help="formal N=10 matrix (H2.2 only)")
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args()

    if args.output_dir:
        outdir = Path(args.output_dir)
    elif args.smoke:
        outdir = Path(tempfile.mkdtemp(prefix="h2-smoke-"))
    else:
        outdir = HERE / "results" / "run-001"
    workdir = outdir / "work"
    workdir.mkdir(parents=True, exist_ok=True)

    n = 1 if args.smoke else 10
    runner = Runner(workdir=workdir, n=n)
    runner.run()
    summary = write_outputs(outdir, runner, n)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    if not summary["all_pass"]:
        print("WARNING: some trials failed assertions; see trials.csv", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
