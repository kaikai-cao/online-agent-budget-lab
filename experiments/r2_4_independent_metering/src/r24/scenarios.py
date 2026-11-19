"""T1-T8 scenarios for R2.4 phase 1.

Each scenario builds REAL evidence in three independent SQLite DBs (witness /
service / observer), applies optional attacks to REAL records or DB rows, then
runs schemes A/B/C over the resulting evidence. No attack touches verifier
internals; no verdict is manufactured.

Capability matrix (what each scheme is EXPECTED to detect):

  T1 normal        A,B,C: none (no false positive)
  T2 under-report  A: blind ; B: MISSING_USAGE_EVENT
                   C: MISSING_USAGE_EVENT + UNKNOWN_EVENT
                   (the independent observer HAS an observation but the service
                    metering record is absent -> an extra cross-source finding)
  T3 delete record A: blind ; B: MISSING_USAGE_EVENT
                   C: MISSING_USAGE_EVENT + UNKNOWN_EVENT (same as T2)
  T4 tamper value  A,B,C: INVALID_SIGNATURE
  T5 duplicate     A,B,C: DUPLICATE_USAGE_EVENT (identical=count once;
                    conflict=reject)
  T6 partial/diff  A,B,C: none expected ; distinct attempt_ids NOT de-duplicated
  T7 false meter   A: blind ; B: blind ; C: USAGE_MISMATCH
                   <-- flagship control: B alone cannot prove numeric truth
  T8 uncertain     A: blind ; B,C: INCOMPLETE_EXECUTION_STATUS

Every scenario runs >= 10 trials with deterministic per-trial seeds.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

from .metering import MeteringObserver
from .models import (
    ExecStatus, UsageEvent, UsageStatus,
    derive_private_key, public_key_fingerprint,
)
from .tool_service import ToolService
from .verifier import VerifyContext, charged_total, verify_scheme

BASE_SEED = 20261119
TRIALS = 10

# Capability expectations, consumed by the result aggregator.
EXPECTED: dict[str, dict[str, list[str]]] = {
    "T1": {"A": [], "B": [], "C": []},
    # Scheme C emits an ADDITIONAL UNKNOWN_EVENT for T2/T3: the independent
    # observer has an observation for the event id but there is no accepted
    # service usage to attach it to. This is preserved (not collapsed into
    # MISSING_USAGE_EVENT) as extra evidence from the independent source.
    "T2": {"A": [], "B": ["MISSING_USAGE_EVENT"],
           "C": ["MISSING_USAGE_EVENT", "UNKNOWN_EVENT"]},
    "T3": {"A": [], "B": ["MISSING_USAGE_EVENT"],
           "C": ["MISSING_USAGE_EVENT", "UNKNOWN_EVENT"]},
    "T4": {"A": ["INVALID_SIGNATURE"], "B": ["INVALID_SIGNATURE"], "C": ["INVALID_SIGNATURE"]},
    "T5": {"A": ["DUPLICATE_USAGE_EVENT"], "B": ["DUPLICATE_USAGE_EVENT"], "C": ["DUPLICATE_USAGE_EVENT"]},
    "T6": {"A": [], "B": [], "C": []},
    "T7": {"A": [], "B": [], "C": ["USAGE_MISMATCH"]},
    "T8": {"A": [], "B": ["INCOMPLETE_EXECUTION_STATUS"], "C": ["INCOMPLETE_EXECUTION_STATUS"]},
}

# Verdicts that must NOT appear (used to confirm a scheme is genuinely blind).
ABSENT: dict[str, dict[str, list[str]]] = {
    "T2": {"A": ["MISSING_USAGE_EVENT"]},
    "T3": {"A": ["MISSING_USAGE_EVENT"]},
    "T7": {"A": ["USAGE_MISMATCH"], "B": ["USAGE_MISMATCH"]},
    "T8": {"A": ["INCOMPLETE_EXECUTION_STATUS"]},
    "T6": {"A": ["DUPLICATE_USAGE_EVENT", "INCOMPLETE_EXECUTION_STATUS"],
           "B": ["DUPLICATE_USAGE_EVENT", "INCOMPLETE_EXECUTION_STATUS"],
           "C": ["DUPLICATE_USAGE_EVENT", "INCOMPLETE_EXECUTION_STATUS"]},
    "T1": {"A": ["MISSING_USAGE_EVENT", "DUPLICATE_USAGE_EVENT", "INVALID_SIGNATURE",
                 "USAGE_MISMATCH", "INCOMPLETE_EXECUTION_STATUS", "UNKNOWN_EVENT",
                 "INVALID_EVENT_LINKAGE"],
           "B": ["MISSING_USAGE_EVENT", "DUPLICATE_USAGE_EVENT", "INVALID_SIGNATURE",
                 "USAGE_MISMATCH", "INCOMPLETE_EXECUTION_STATUS", "UNKNOWN_EVENT",
                 "INVALID_EVENT_LINKAGE"],
           "C": ["MISSING_USAGE_EVENT", "DUPLICATE_USAGE_EVENT", "INVALID_SIGNATURE",
                 "USAGE_MISMATCH", "INCOMPLETE_EXECUTION_STATUS", "UNKNOWN_EVENT",
                 "INVALID_EVENT_LINKAGE"]},
}


@dataclass
class TrialRecord:
    scenario: str
    trial: int
    seed: int
    run_id: str
    attack: str
    # full event evidence (for independent audit / typical-case display)
    execution_events: list[dict[str, Any]] = field(default_factory=list)
    usage_events: list[dict[str, Any]] = field(default_factory=list)
    # Ground truth in service DBs (may differ from what coordinator submits).
    service_db_usage_events: list[dict[str, Any]] = field(default_factory=list)
    # What the (untrusted) coordinator actually submitted to the verifier.
    coordinator_submitted_usage_events: list[dict[str, Any]] = field(default_factory=list)
    # event_ids the coordinator deliberately dropped from the aggregation input.
    coordinator_deleted_event_ids: list[str] = field(default_factory=list)
    observations: list[dict[str, Any]] = field(default_factory=list)
    key_fingerprints: dict[str, str] = field(default_factory=dict)
    # per-scheme outcome
    schemes: dict[str, dict[str, Any]] = field(default_factory=dict)
    # expected / absent for this scenario (from matrices)
    expected: dict[str, list[str]] = field(default_factory=dict)
    absent: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario, "trial": self.trial, "seed": self.seed,
            "run_id": self.run_id, "attack": self.attack,
            "execution_events": self.execution_events,
            "usage_events": self.usage_events,
            "service_db_usage_events": self.service_db_usage_events,
            "coordinator_submitted_usage_events": self.coordinator_submitted_usage_events,
            "coordinator_deleted_event_ids": self.coordinator_deleted_event_ids,
            "observations": self.observations,
            "key_fingerprints": self.key_fingerprints,
            "schemes": self.schemes,
            "expected": self.expected, "absent": self.absent,
        }


def _eid(run_id: str, svc: str, op: str, attempt: str) -> str:
    return f"{run_id}:{svc}:{op}:{attempt}"


def _walk_status(witness, event_id: str, target: str) -> None:
    """Walk from REGISTERED to target along LEGAL transitions only.

    REGISTERED -> DISPATCHED -> {MEASURED | UNCERTAIN};
    MEASURED -> FINALIZED.  Every step must be accepted by the witness's
    enforced state machine; a rejected step is a scenario bug, so assert.
    """
    steps: list[str] = [ExecStatus.DISPATCHED.value]
    if target == ExecStatus.UNCERTAIN.value:
        steps.append(ExecStatus.UNCERTAIN.value)
    elif target == ExecStatus.MEASURED.value:
        steps.append(ExecStatus.MEASURED.value)
    elif target == ExecStatus.FINALIZED.value:
        steps += [ExecStatus.MEASURED.value, ExecStatus.FINALIZED.value]
    elif target != ExecStatus.DISPATCHED.value:
        raise ValueError(f"no legal walk defined to {target}")
    for st in steps:
        if not witness.advance_status(event_id, st):
            raise RuntimeError(
                f"illegal/rejected transition {event_id} -> {st} (state machine enforcement)"
            )


def _register_and_emit(
    witness, svc_a: ToolService, svc_b: ToolService, observer: MeteringObserver,
    run_id: str, op: str, attempt: str, svc: str,
    reported: int, observed: int, final_status: str = ExecStatus.FINALIZED.value,
    usage_status: str = UsageStatus.MEASURED.value,
) -> tuple[str, Any, Any, Any]:
    event_id = _eid(run_id, svc, op, attempt)
    ee = witness.register_intent(
        run_id=run_id, service_id=svc, operation_id=op, attempt_id=attempt,
        event_id=event_id, request_digest=f"sha256:req-{op}-{attempt}",
        registered_at=f"t-{witness.event_count()+1:03d}",
    )
    _walk_status(witness, event_id, final_status)
    ue = (svc_a if svc == "A" else svc_b).emit_usage(
        event_id=event_id, run_id=run_id, operation_id=op, attempt_id=attempt,
        reported_usage=reported, status=usage_status,
    )
    ob = observer.observe(event_id=event_id, observed_usage=observed)
    return event_id, ee, ue, ob


def _run_schemes(witness, svc_a, svc_b, observer, pubkeys,
                 submitted_usage: list | None = None) -> dict[str, Any]:
    # The verifier consumes whatever the (untrusted) coordinator SUBMITS, not
    # necessarily the full service DB. Honest scenarios submit everything; T3
    # deliberately omits one record from this list while the service DB keeps it.
    usage_events = (list(submitted_usage) if submitted_usage is not None
                    else svc_a.all_events() + svc_b.all_events())
    exec_events = witness.all_events()
    observations = observer.all_observations()
    base = VerifyContext(usage_events=usage_events, service_pubkeys=pubkeys)
    out: dict[str, Any] = {}
    for scheme in ("A", "B", "C"):
        ctx = VerifyContext(
            usage_events=usage_events,
            service_pubkeys=pubkeys,
            execution_events=(exec_events if scheme in ("B", "C") else None),
            witness_pubkey=(pubkeys["witness"] if scheme in ("B", "C") else None),
            observations=(observations if scheme == "C" else None),
            observer_pubkey=(pubkeys["observer"] if scheme == "C" else None),
        )
        results = verify_scheme(scheme, ctx)
        verdict_names = sorted({r.verdict for r in results})
        # A benign identical duplicate is billed once and does not block
        # settlement; every other finding blocks it. In T8 the INCOMPLETE
        # finding makes settleable=False -- it must NOT be settled as zero.
        blocking = {
            v for v in verdict_names
            if not (v == "DUPLICATE_USAGE_EVENT"
                    and all(r.detail.get("duplicate_kind") == "identical"
                            for r in results if r.verdict == v))
        }
        out[scheme] = {
            "verdicts": [r.to_dict() for r in results],
            "verdict_names": verdict_names,
            "charged_total": charged_total(results, ctx),
            "settleable": len(blocking) == 0,
            "blocking_verdicts": sorted(blocking),
        }
    return out


def run_trial(scenario: str, trial: int, workroot: Path | None = None) -> TrialRecord:
    """Run one trial of one scenario with fully isolated DBs."""
    seed = BASE_SEED + trial
    run_id = f"run-{scenario}-t{trial:02d}"
    tmp = tempfile.TemporaryDirectory(prefix=f"r24-{scenario}-{trial}-")
    wd = Path(workroot) if workroot else Path(tmp.name)
    wd.mkdir(parents=True, exist_ok=True)

    # disjoint deterministic keys, one per independent domain
    w_key = derive_private_key(seed, "witness")
    a_key = derive_private_key(seed, "service_A")
    b_key = derive_private_key(seed, "service_B")
    o_key = derive_private_key(seed, "observer")
    pubkeys: dict[str, Ed25519PublicKey] = {
        "A": a_key.public_key(), "B": b_key.public_key(),
        "witness": w_key.public_key(), "observer": o_key.public_key(),
    }
    from .witness import EventWitness
    witness = EventWitness(wd / "witness.sqlite3", w_key, ["A", "B"])
    svc_a = ToolService("A", wd / "svc_a.sqlite3", a_key)
    svc_b = ToolService("B", wd / "svc_b.sqlite3", b_key)
    observer = MeteringObserver("observer-01", wd / "observer.sqlite3", o_key)

    attack = "none"
    submitted_usage: list | None = None       # verifier input (coordinator aggregation)
    coordinator_deleted_ids: list[str] = []   # records dropped by coordinator
    if scenario == "T1":
        # normal: A=300, B=200 -> 500
        _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op1", "att0", "A", 300, 300)
        _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op2", "att0", "B", 200, 200)

    elif scenario == "T2":
        # service under-reporting: witness registers B op, service never submits usage
        attack = "service_under_reports_A"
        _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op1", "att0", "A", 300, 300)
        eid2 = _eid(run_id, "B", "op2", "att0")
        ee2 = witness.register_intent(run_id, "B", "op2", "att0", eid2,
                                      "sha256:req-op2-att0", "t-003")
        _walk_status(witness, eid2, ExecStatus.FINALIZED.value)
        # NO svc emit -> missing usage in real service DB
        observer.observe(event_id=eid2, observed_usage=200)

    elif scenario == "T3":
        # Coordinator deletes a metering row from the AGGREGATION INPUT it
        # submits to the verifier. Distinct from T2: here the service DB DOES
        # hold a valid signed usage event (ground truth intact); only the
        # untrusted coordinator's summary omits it. Witness keeps full record.
        attack = "coordinator_deletes_from_aggregation_input"
        _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op1", "att0", "A", 300, 300)
        eid2, _, _, _ = _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op2", "att0", "B", 200, 200)
        # service DB still contains BOTH records; coordinator drops eid2 when
        # building the aggregation input handed to the verifier.
        coordinator_deleted_ids = [eid2]
        submitted_usage = [u for u in (svc_a.all_events() + svc_b.all_events())
                           if u.event_id != eid2]

    elif scenario == "T4":
        # tamper signed value without re-signing
        attack = "tamper_signed_usage_value"
        eid1, _, _, _ = _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op1", "att0", "A", 300, 300)
        _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op2", "att0", "B", 200, 200)
        svc_a.tamper_usage_value(eid1, 999)  # signature no longer valid

    elif scenario == "T5":
        # duplicate: identical (count once) + conflict (reject)
        attack = "duplicate_identical_and_conflict"
        eid1, _, ue1, _ = _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op1", "att0", "A", 300, 300)
        svc_a.reemit_same_event_same_content(ue1)  # identical duplicate
        eid2, _, _, _ = _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op2", "att0", "B", 200, 200)
        forged = UsageEvent(event_id=eid2, run_id=run_id, operation_id="op2",
                            attempt_id="att0", usage=250, unit="unit",
                            status=UsageStatus.MEASURED.value, source_id="B").sign(b_key)
        svc_b.reemit_same_event_different_content(forged)  # conflict

    elif scenario == "T6":
        # partial execution, two DISTINCT attempts -> must NOT be de-duplicated
        attack = "two_distinct_attempts_not_deduped"
        _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op1", "att1", "A", 30, 30,
                           final_status=ExecStatus.FINALIZED.value)
        _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op1", "att2", "A", 20, 20,
                           final_status=ExecStatus.FINALIZED.value)

    elif scenario == "T7":
        # flagship: real consumption 250, service signs & reports 100
        attack = "service_false_metering_actual_250_reported_100"
        _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op1", "att0", "A", 100, 250)
        _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op2", "att0", "B", 200, 200)

    elif scenario == "T8":
        # stuck UNCERTAIN: registered, no usage submitted -> must not settle as zero
        attack = "execution_uncertain_no_settlement"
        _register_and_emit(witness, svc_a, svc_b, observer, run_id, "op1", "att0", "A", 300, 300)
        eid2 = _eid(run_id, "B", "op2", "att0")
        witness.register_intent(run_id, "B", "op2", "att0", eid2,
                                "sha256:req-op2-att0", "t-003")
        _walk_status(witness, eid2, ExecStatus.UNCERTAIN.value)  # stuck at UNCERTAIN
        # no usage emitted for eid2; a naive aggregator would bill 0 silently
        observer.observe(event_id=eid2, observed_usage=200)
    else:
        raise ValueError(f"unknown scenario {scenario}")

    service_db_usage = svc_a.all_events() + svc_b.all_events()
    submitted_for_verify = (submitted_usage if submitted_usage is not None
                            else list(service_db_usage))
    schemes = _run_schemes(witness, svc_a, svc_b, observer, pubkeys,
                           submitted_usage=submitted_for_verify)
    rec = TrialRecord(
        scenario=scenario, trial=trial, seed=seed, run_id=run_id, attack=attack,
        execution_events=[e.to_dict() for e in witness.all_events()],
        usage_events=[u.to_dict() for u in submitted_for_verify],
        service_db_usage_events=[u.to_dict() for u in service_db_usage],
        coordinator_submitted_usage_events=[u.to_dict() for u in submitted_for_verify],
        coordinator_deleted_event_ids=coordinator_deleted_ids,
        observations=[o.to_dict() for o in observer.all_observations()],
        key_fingerprints={
            "witness": public_key_fingerprint(pubkeys["witness"]),
            "service_A": public_key_fingerprint(pubkeys["A"]),
            "service_B": public_key_fingerprint(pubkeys["B"]),
            "observer": public_key_fingerprint(pubkeys["observer"]),
        },
        schemes=schemes,
        expected=EXPECTED.get(scenario, {}),
        absent=ABSENT.get(scenario, {}),
    )
    tmp.cleanup()
    return rec
