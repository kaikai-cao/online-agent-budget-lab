"""T1-T5 scenarios for the Phase-2 discrimination experiment.

Per (scenario, trial) we build FOUR isolated worlds — one per scheme P0-P3 —
and run the SAME physical call attempts in each. What differs is only the
scheme's ARCHITECTURE (P0 has no gateway; P1-P3 have a mandatory gateway;
P2/P3 add an independent ingress observer; P3 adds witness expectations). No
scheme receives a more favorable attack condition.

Ground truth (service_executed etc.) is recorded by this controller only and
is kept SEPARATE from the ObservableEvidence handed to the verifier. Verifier
functions never see it.

Scenarios
  T1 normal        agent -> gateway -> service, all evidence present
  T2 bypass        agent calls service directly (skips gateway)
  T3 no report     service executes but submits no self-report
  T4 retry/dup     two distinct attempts + a duplicate resubmission
  T5 obs failure   service executed+reported, ingress observer record lost
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .gateway import Gateway
from .ground_truth import GroundTruthStore
from .ingress_observer import IngressObserver
from .models import (
    GroundTruthEvent, Verdict, derive_key, fingerprint,
)
from .service import RejectedByGateway, ToolService
from .verifier import SCHEMES, ObservableEvidence, verify_scheme
from .witness import CallWitness

BASE_SEED = 20261120
TRIALS = 10
SCENARIOS = ("T1", "T2", "T3", "T4", "T5")

# Pre-registered expectations (hypotheses, NOT results). Each maps scenario ->
# scheme -> set of verdict results expected for the scheme's anchor call(s).
# The runner checks actual vs these; see experiment_report.md.
EXPECTED: dict[str, dict[str, list[str]]] = {
    "T1": {s: ["COVERED"] for s in SCHEMES},
    # T2: P0 has no gateway so the direct call just executes+reports (COVERED);
    # P1 rejects at the entrance (no execution -> no verdict) ; P2/P3 observe an
    # unauthenticated entrance request -> BYPASS_DETECTED.
    "T2": {
        "P0": ["COVERED"],
        "P1": [],
        "P2": ["BYPASS_DETECTED"],
        "P3": ["BYPASS_DETECTED"],
    },
    # T3: service executed, no self-report. P0 has no anchor -> nothing; P1 sees
    # gateway forward without submission -> MISSING; P2/P3 same + ingress.
    "T3": {
        "P0": [], "P1": ["MISSING_EVIDENCE"],
        "P2": ["MISSING_EVIDENCE"], "P3": ["MISSING_EVIDENCE"],
    },
    # T4: two distinct attempts + a duplicate. P0 merges -> one DUPLICATE_IGNORED
    # (one bill for TWO executions = a duplicate-metering error); P1-P3 keep both
    # attempts distinct: one COVERED + one DUPLICATE_IGNORED (the true repeat).
    "T4": {
        "P0": ["DUPLICATE_IGNORED"],
        "P1": ["COVERED", "DUPLICATE_IGNORED"],
        "P2": ["COVERED", "DUPLICATE_IGNORED"],
        "P3": ["COVERED", "DUPLICATE_IGNORED"],
    },
    # T5: observer record lost. P0/P1 still COVERED (gateway evidence); P2/P3
    # must return UNCERTAIN rather than claim completeness.
    "T5": {
        "P0": ["COVERED"], "P1": ["COVERED"],
        "P2": ["UNCERTAIN"], "P3": ["UNCERTAIN"],
    },
}


@dataclass
class TrialRecord:
    scenario: str
    trial: int
    seed: int
    schemes: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario, "trial": self.trial, "seed": self.seed,
            "schemes": self.schemes,
        }


@dataclass
class _World:
    """One scheme's isolated deployment for one trial."""
    scheme: str
    root: Path
    gateway: Gateway | None
    service: ToolService
    ingress: IngressObserver | None
    witness: CallWitness | None
    gt: GroundTruthStore
    keys: dict[str, Any]
    pubkeys: dict[str, Ed25519PublicKey]


def _build_world(scheme: str, root: Path, seed: int) -> _World:
    w_key = derive_key(seed, "witness")
    g_key = derive_key(seed, "gateway")
    s_key = derive_key(seed, "service")
    i_key = derive_key(seed, "ingress")
    pubkeys = {
        "witness": w_key.public_key(), "gateway": g_key.public_key(),
        "service": s_key.public_key(), "ingress": i_key.public_key(),
    }
    has_gateway = scheme in {"P1", "P2", "P3"}
    gateway = Gateway(root / "gateway.sqlite3", g_key, "gw-01") if has_gateway else None
    service = ToolService(
        root / "service.sqlite3", s_key,
        g_key.public_key(), "gw-01", "svc-A",
        enforce_gateway=(scheme != "P0"), track_attempt=(scheme != "P0"),
    )
    ingress = (IngressObserver(root / "ingress.sqlite3", i_key, "obs-01")
               if scheme in {"P2", "P3"} else None)
    witness = (CallWitness(root / "witness.sqlite3", w_key, "wit-01")
               if scheme == "P3" else None)
    return _World(scheme, root, gateway, service, ingress, witness,
                  GroundTruthStore(),
                  {"witness": w_key, "gateway": g_key, "service": s_key, "ingress": i_key},
                  pubkeys)


def _gt_event(w: _World, run_id: str, call_id: str, attempt: str, *,
              gw_received: bool, gw_forwarded: bool, accepted: bool,
              executed: bool, note: str = "") -> GroundTruthEvent:
    ev = GroundTruthEvent(
        run_id=run_id, logical_call_id=call_id, attempt_id=attempt,
        service_id="svc-A", gateway_received=gw_received,
        gateway_forwarded=gw_forwarded, service_accepted=accepted,
        service_executed=executed, note=note,
    )
    w.gt.record(ev)  # controller-only; never passed to verifier
    return ev


def _observe_ingress(w: _World, run_id: str, call_id: str, attempt: str,
                     gateway_authenticated: bool, drop: bool = False) -> None:
    if w.ingress is None:
        return
    w.ingress.observe(run_id, call_id, attempt, "svc-A",
                      gateway_authenticated, drop_record=drop)


def _expect(w: _World, run_id: str, call_id: str, attempt: str) -> None:
    if w.witness is not None:
        w.witness.expect(run_id, call_id, attempt, "svc-A")


def _run_world(w: _World, scenario: str, run_id: str) -> None:
    s = w.scheme
    if scenario == "T1":
        call, att = "call-1", "att-1"
        _expect(w, run_id, call, att)
        fwd = w.gateway.forward(run_id, call, att, "svc-A") if w.gateway else None
        _observe_ingress(w, run_id, call, att, gateway_authenticated=True)
        w.service.receive(fwd, run_id, call, att)
        _gt_event(w, run_id, call, att,
                  gw_received=bool(fwd), gw_forwarded=bool(fwd),
                  accepted=True, executed=True)

    elif scenario == "T2":
        # Direct call to service with NO gateway receipt (bypass).
        call, att = "call-bypass", "att-1"
        _observe_ingress(w, run_id, call, att, gateway_authenticated=False)
        try:
            w.service.receive(None, run_id, call, att)  # no gateway receipt
            accepted, executed = True, True
        except RejectedByGateway:
            accepted, executed = False, False  # true enforcement: no execution
        _gt_event(w, run_id, call, att,
                  gw_received=False, gw_forwarded=False,
                  accepted=accepted, executed=executed,
                  note="direct call bypassing gateway entrance")

    elif scenario == "T3":
        # Service executed but did NOT submit a self-report.
        call, att = "call-noreport", "att-1"
        _expect(w, run_id, call, att)
        fwd = w.gateway.forward(run_id, call, att, "svc-A") if w.gateway else None
        _observe_ingress(w, run_id, call, att, gateway_authenticated=True)
        w.service.receive(fwd, run_id, call, att, suppress_report=True)
        _gt_event(w, run_id, call, att,
                  gw_received=bool(fwd), gw_forwarded=bool(fwd),
                  accepted=True, executed=True, note="executed, report suppressed")

    elif scenario == "T4":
        # Two DISTINCT attempts of one logical call + a duplicate resubmission.
        call, a1, a2 = "call-retry", "att-1", "att-2"
        _expect(w, run_id, call, a1)
        _expect(w, run_id, call, a2)
        f1 = w.gateway.forward(run_id, call, a1, "svc-A") if w.gateway else None
        f2 = w.gateway.forward(run_id, call, a2, "svc-A") if w.gateway else None
        _observe_ingress(w, run_id, call, a1, gateway_authenticated=True)
        _observe_ingress(w, run_id, call, a2, gateway_authenticated=True)
        _, sub1 = w.service.receive(f1, run_id, call, a1)
        w.service.receive(f2, run_id, call, a2)
        if sub1 is not None:
            w.service.resubmit(sub1)  # duplicate transmission of same attempt
        for a in (a1, a2):
            _gt_event(w, run_id, call, a,
                      gw_received=True, gw_forwarded=True,
                      accepted=True, executed=True,
                      note="distinct attempt" + (" (dup submitted)" if a == a1 else ""))

    elif scenario == "T5":
        # Executed and reported, but independent ingress observation is lost.
        call, att = "call-obslost", "att-1"
        _expect(w, run_id, call, att)
        fwd = w.gateway.forward(run_id, call, att, "svc-A") if w.gateway else None
        _observe_ingress(w, run_id, call, att, gateway_authenticated=True, drop=True)
        w.service.receive(fwd, run_id, call, att)
        _gt_event(w, run_id, call, att,
                  gw_received=bool(fwd), gw_forwarded=bool(fwd),
                  accepted=True, executed=True, note="ingress observation lost")
    else:
        raise ValueError(f"unknown scenario {scenario}")


def _evidence(w: _World) -> ObservableEvidence:
    return ObservableEvidence(
        submissions=w.service.submissions(),
        forward_receipts=(w.gateway.receipts() if w.gateway else []),
        ingress_observations=(w.ingress.observations() if w.ingress else []),
        expectations=(w.witness.expectations() if w.witness else []),
        service_pubkey=w.pubkeys["service"],
        gateway_pubkey=w.pubkeys["gateway"],
        ingress_pubkey=w.pubkeys["ingress"],
        witness_pubkey=w.pubkeys["witness"],
    )


def run_trial(scenario: str, trial: int) -> TrialRecord:
    seed = BASE_SEED + trial
    run_id = f"run-{scenario}-t{trial:02d}"
    rec = TrialRecord(scenario=scenario, trial=trial, seed=seed)
    for scheme in SCHEMES:
        tmp = tempfile.TemporaryDirectory(prefix=f"r24p2-{scheme}-{scenario}-{trial}-")
        root = Path(tmp.name)
        w = _build_world(scheme, root, seed)
        try:
            _run_world(w, scenario, run_id)
            obs_ev = _evidence(w)
            # Each scheme's verifier sees ONLY that scheme's observable evidence.
            findings = verify_scheme(scheme, obs_ev)
            evidence_summary = {
                "submissions": len(obs_ev.submissions),
                "forward_receipts": len(obs_ev.forward_receipts),
                "ingress_observations": len(obs_ev.ingress_observations),
                "expectations": len(obs_ev.expectations),
            }
        finally:
            tmp.cleanup()

        gt_events = [e.to_dict() for e in w.gt.all()]
        rec.schemes[scheme] = {
            "architecture": {
                "mandatory_gateway": scheme != "P0",
                "ingress_observer": scheme in {"P2", "P3"},
                "witness_expectations": scheme == "P3",
            },
            "ground_truth": gt_events,                 # controller-only facts
            "observable_summary": evidence_summary,
            "verdicts": [v.to_dict() for v in findings],
            "key_fingerprints": {k: fingerprint(v) for k, v in w.pubkeys.items()},
        }
    return rec
