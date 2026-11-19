"""Verifier with four escalating schemes P0-P3.

CRITICAL ISOLATION
------------------
Every ``verify_*`` function accepts ONLY signed observable records + public
keys. It has NO parameter and NO import through which ground truth could enter.
``service_executed`` is never visible here. The four evaluation metrics are
computed by the CONTROLLER (run_experiments.py) by joining verifier verdicts to
ground truth — the verifier itself never scores against the answer.

What each scheme can OBSERVE (evidence stack):
  P0  service self-report submissions only
  P1  + gateway forward receipts (mandatory-gateway evidence)
  P2  + independent ingress observations
  P3  + witness expectations (expected call set)

Honesty rules encoded here:
  * gateway_forwarded receipt proves a request crossed the gateway, NOT that the
    service executed -> in P1 a forwarded-but-unreported call is MISSING_EVIDENCE,
    never COVERED.
  * service_accepted / submission proves the SERVICE CLAIMS it ran, never ground
    truth execution.
  * an ingress observation proves a request reached the service entrance, not
    that business logic succeeded.
  * absence of independent observation with other evidence present => UNCERTAIN
    (do NOT silently treat a missing observer record as "nothing happened").
  * dedup is by (logical_call_id, attempt_id); P0 has no attempt tracking so
    retries collapse into one (that is exactly the P0 weakness T4 exposes).

No ZKP/Halo2/TEE. No ground-truth access.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import (
    FinalResult, ForwardReceipt, IngressObservation, ServiceSubmission,
    Verdict, WitnessExpectation, assert_no_ground_truth,
)

SCHEMES = ("P0", "P1", "P2", "P3")


@dataclass
class ObservableEvidence:
    """The ONLY thing a verifier sees. Contains no ground-truth fields."""
    submissions: list[ServiceSubmission]
    forward_receipts: list[ForwardReceipt]
    ingress_observations: list[IngressObservation]
    expectations: list[WitnessExpectation]
    service_pubkey: Ed25519PublicKey
    gateway_pubkey: Ed25519PublicKey
    ingress_pubkey: Ed25519PublicKey
    witness_pubkey: Ed25519PublicKey

    def __post_init__(self):
        assert_no_ground_truth(self)


def _valid(ev, key) -> bool:
    return ev.is_valid(key)


def _key(logical_call_id: str, attempt_id: str) -> str:
    return f"{logical_call_id}|{attempt_id}"


def _verify(scheme: str, ev: ObservableEvidence) -> list[Verdict]:
    """Core verifier. Returns one verdict per anchor call it can observe.

    Anchoring differs by scheme:
      P0 anchors on submissions.
      P1 anchors on the UNION of submissions and gateway receipts.
      P2 anchors on that union plus ingress observations.
      P3 anchors on that union plus witness expectations.
    """
    assert scheme in SCHEMES, f"unknown scheme {scheme}"

    # --- validate signatures; drop invalid evidence, remember detail ---------
    subs = [s for s in ev.submissions if _valid(s, ev.service_pubkey)]
    fwds = [f for f in ev.forward_receipts if _valid(f, ev.gateway_pubkey)]
    ings = ([o for o in ev.ingress_observations if _valid(o, ev.ingress_pubkey)]
            if scheme in {"P2", "P3"} else [])
    exps = ([w for w in ev.expectations if _valid(w, ev.witness_pubkey)]
            if scheme == "P3" else [])

    sub_by = {_key(s.logical_call_id, s.attempt_id): s for s in subs}
    fwd_by = {_key(f.logical_call_id, f.attempt_id): f for f in fwds}
    ing_by = {_key(o.logical_call_id, o.attempt_id): o for o in ings}
    exp_by = {_key(w.logical_call_id, w.attempt_id): w for w in exps}

    # duplicate transmissions: count how many raw submissions share a key
    sub_counts: dict[str, int] = {}
    for s in subs:
        k = _key(s.logical_call_id, s.attempt_id)
        sub_counts[k] = sub_counts.get(k, 0) + 1

    if scheme == "P0":
        anchors = set(sub_by.keys())
    elif scheme == "P1":
        anchors = set(fwd_by) | set(sub_by)
    elif scheme == "P2":
        anchors = set(fwd_by) | set(sub_by) | set(ing_by)
    else:  # P3
        anchors = set(fwd_by) | set(sub_by) | set(ing_by) | set(exp_by)

    verdicts: list[Verdict] = []
    for k in sorted(anchors):
        logical, attempt = k.split("|", 1)
        has_sub = k in sub_by
        has_fwd = k in fwd_by
        has_ing = k in ing_by
        has_exp = k in exp_by
        detail = {
            "has_submission": has_sub, "has_gateway_forward": has_fwd,
            "has_ingress_observation": has_ing, "has_witness_expectation": has_exp,
            "submission_count": sub_counts.get(k, 0),
        }

        if scheme == "P0":
            # Service self-report only. A submission is taken at face value;
            # with no gateway / witness there is NO anchor for an unreported
            # call, and no attempt_id to tell retries from duplicates.
            if has_sub:
                if sub_counts[k] > 1:
                    verdicts.append(Verdict(scheme, logical, attempt,
                        FinalResult.DUPLICATE_IGNORED,
                        "P0 counts same (call,blank-attempt) once; cannot tell a "
                        "distinct retry from a duplicate", detail))
                else:
                    verdicts.append(Verdict(scheme, logical, attempt,
                        FinalResult.COVERED,
                        "P0 accepts service self-report as coverage", detail))
            continue

        # P1+: gateway-forwarded but unreported => evidence gap, never "covered".
        if has_fwd and not has_sub:
            verdicts.append(Verdict(scheme, logical, attempt,
                FinalResult.MISSING_EVIDENCE,
                "gateway forwarded but no service submission; gateway receipt "
                "proves traversal, NOT execution", detail))
            continue

        if has_sub and not has_fwd:
            # A service claim with no gateway receipt: bypass evidence (or a
            # service that never traversed the mandatory gateway).
            verdicts.append(Verdict(scheme, logical, attempt,
                FinalResult.BYPASS_DETECTED,
                "service reports a call with no valid gateway forward receipt",
                detail))
            continue

        if has_sub and has_fwd:
            # P2/P3: independent ingress observation is required to call it
            # covered. If it is missing while other evidence exists, we must not
            # silently conclude completeness -> UNCERTAIN.
            if scheme in {"P2", "P3"}:
                if not has_ing:
                    verdicts.append(Verdict(scheme, logical, attempt,
                        FinalResult.UNCERTAIN,
                        "submission+gateway exist but independent ingress "
                        "evidence is absent -> not provably complete",
                        detail))
                    continue
                # ingress saw the request but it was NOT gateway-authenticated
                if not ing_by[k].gateway_authenticated:
                    verdicts.append(Verdict(scheme, logical, attempt,
                        FinalResult.BYPASS_DETECTED,
                        "ingress observed a request lacking valid gateway proof",
                        detail))
                    continue
            if sub_counts[k] > 1:
                verdicts.append(Verdict(scheme, logical, attempt,
                    FinalResult.DUPLICATE_IGNORED,
                    "same (call,attempt) submitted more than once; counted once",
                    detail))
                continue
            # P3: an expectation must exist for full coverage.
            if scheme == "P3" and not has_exp:
                verdicts.append(Verdict(scheme, logical, attempt,
                    FinalResult.MISSING_EVIDENCE,
                    "evidence present but no witness expectation for this call",
                    detail))
                continue
            verdicts.append(Verdict(scheme, logical, attempt,
                FinalResult.COVERED,
                "observable evidence supports coverage (execution still not "
                "ground truth)", detail))
            continue

        # ingress or expectation only, no submission and no gateway forward
        if scheme in {"P2", "P3"} and has_ing and not has_fwd and not has_sub:
            verdicts.append(Verdict(scheme, logical, attempt,
                FinalResult.BYPASS_DETECTED if not ing_by[k].gateway_authenticated
                else FinalResult.MISSING_EVIDENCE,
                "ingress saw entrance request without matching submission/forward",
                detail))
            continue

        if scheme == "P3" and has_exp and not has_fwd and not has_sub and not has_ing:
            verdicts.append(Verdict(scheme, logical, attempt,
                FinalResult.MISSING_EVIDENCE,
                "witness expected this call but no evidence appeared", detail))
            continue

        # fallback: observable anchor with no decisive evidence
        verdicts.append(Verdict(scheme, logical, attempt,
            FinalResult.NO_EVIDENCE, "insufficient observable evidence", detail))

    return verdicts


def verify_scheme(scheme: str, ev: ObservableEvidence) -> list[Verdict]:
    """Public entry point: verify one scheme against observable evidence only."""
    return _verify(scheme, ev)


def verify_all_schemes(ev: ObservableEvidence) -> dict[str, list[Verdict]]:
    return {s: _verify(s, ev) for s in SCHEMES}
