"""Evidence verifier with three escalating schemes A / B / C.

 Scheme A - ordinary signed metering:
   Inputs: usage events + service public keys only.
   Checks: signature, duplicate linkage, duplicate conflict.
   CAN detect: tampered value (signature breaks), duplicate/conflict.
   CANNOT detect: a missing usage event (no independent expectation), a value
   the service itself signed dishonestly, an UNCERTAIN status settled as zero.

 Scheme B - A + independent event witness:
   Adds Witness execution events -> can detect MISSING_USAGE_EVENT,
   UNKNOWN_EVENT, INVALID_EVENT_LINKAGE, INCOMPLETE_EXECUTION_STATUS.
   STILL CANNOT prove the numeric usage is true (witness registers intent, not
   resource consumption). This is the crucial boundary.

 Scheme C - B + independent metering observation:
   Adds signed observations -> can detect USAGE_MISMATCH (service claim vs
   independent observation).

Duplicate rule:
  - same event_id + same signed payload -> count ONCE, flag DUPLICATE.
  - same event_id + different payload -> DUPLICATE conflict (reject).
  - different attempt_id -> distinct attempts, never de-duplicated.

Important: the verifier NEVER mutates the records it checks, and attacks never
touch the verifier internals. Evidence is read from the three real DBs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import (
    ExecStatus,
    ExecutionEvent,
    MeteringObservation,
    UsageEvent,
    VerificationResult,
    Verdict,
    verify_payload,
)


@dataclass
class VerifyContext:
    usage_events: list[UsageEvent]
    service_pubkeys: dict[str, Ed25519PublicKey]
    execution_events: list[ExecutionEvent] | None = None
    witness_pubkey: Ed25519PublicKey | None = None
    observations: list[MeteringObservation] | None = None
    observer_pubkey: Ed25519PublicKey | None = None


def _u(event_id: str, scheme: str, reason: str, **detail: object) -> VerificationResult:
    return VerificationResult(
        verdict=Verdict.ACCEPTED.value, scheme=scheme, event_id=event_id,
        reason=reason, detail=dict(detail),
    )


def _v(verdict: Verdict, event_id: str, scheme: str, reason: str, **detail: object) -> VerificationResult:
    return VerificationResult(
        verdict=verdict.value, scheme=scheme, event_id=event_id,
        reason=reason, detail=dict(detail),
    )


def _verify_witness_signature(ev: ExecutionEvent, key: Ed25519PublicKey) -> bool:
    return verify_payload(key, ev.witness_signature, ev.signed_payload())


def _verify_observation_signature(ob: MeteringObservation, key: Ed25519PublicKey) -> bool:
    return verify_payload(key, ob.signature, ob.signed_payload())


def _usage_digest(ev: UsageEvent) -> str:
    # digest of the SIGNED payload; two "same content" records hash equal.
    from .models import digest
    return digest(ev.signed_payload())


def verify_scheme(scheme: str, ctx: VerifyContext) -> list[VerificationResult]:
    """Verify all evidence under one scheme. Returns one result per finding."""
    if scheme not in {"A", "B", "C"}:
        raise ValueError(f"unknown scheme {scheme}")
    results: list[VerificationResult] = []

    # --- service-side signature + duplicate handling (all schemes) ---
    seen_content: dict[str, str] = {}   # event_id -> signed-payload digest
    seen_attempts: dict[str, str] = {}  # event_id -> attempt_id
    accepted_usage: dict[str, UsageEvent] = {}

    for ev in ctx.usage_events:
        pub = ctx.service_pubkeys.get(ev.source_id)
        if pub is None:
            results.append(_v(Verdict.UNKNOWN_EVENT, ev.event_id, scheme,
                              "no public key for source_id", source_id=ev.source_id))
            continue
        if not verify_payload(pub, ev.signature, ev.signed_payload()):
            results.append(_v(Verdict.INVALID_SIGNATURE, ev.event_id, scheme,
                              "usage signature does not verify over canonical payload",
                              source_id=ev.source_id))
            continue

        d = _usage_digest(ev)
        if ev.event_id in seen_content:
            if seen_content[ev.event_id] == d:
                results.append(_v(Verdict.DUPLICATE_USAGE_EVENT, ev.event_id, scheme,
                                  "identical signed record repeated; counted once",
                                  duplicate_kind="identical", content_digest=d))
                continue
            else:
                results.append(_v(Verdict.DUPLICATE_USAGE_EVENT, ev.event_id, scheme,
                                  "same event_id with DIFFERENT signed content; conflict rejected",
                                  duplicate_kind="conflict",
                                  first_digest=seen_content[ev.event_id], second_digest=d))
                continue
        seen_content[ev.event_id] = d
        seen_attempts[ev.event_id] = ev.attempt_id
        accepted_usage[ev.event_id] = ev

    # --- non-settleable usage status must not be counted as zero or finalized ---
    for ev in accepted_usage.values():
        if ev.status in {"UNCERTAIN", "PARTIAL"}:
            results.append(_v(Verdict.INCOMPLETE_EXECUTION_STATUS, ev.event_id, scheme,
                              "usage status not settleable; must not settle as zero",
                              status=ev.status))

    # --- witness cross-check (schemes B, C) ---
    if scheme in {"B", "C"}:
        assert ctx.execution_events is not None and ctx.witness_pubkey is not None
        by_event: dict[str, ExecutionEvent] = {}
        for ee in ctx.execution_events:
            if not _verify_witness_signature(ee, ctx.witness_pubkey):
                results.append(_v(Verdict.INVALID_SIGNATURE, ee.event_id, scheme,
                                  "witness event signature invalid"))
                continue
            if ee.event_id in by_event:
                results.append(_v(Verdict.DUPLICATE_USAGE_EVENT, ee.event_id, scheme,
                                  "duplicate witness event"))
                continue
            by_event[ee.event_id] = ee

        # every witness event must have a matching, correctly-linked usage event
        for ee in by_event.values():
            ue = accepted_usage.get(ee.event_id)

            # An UNCERTAIN/PARTIAL witness status must be flagged INDEPENDENTLY
            # of whether a usage record exists. Otherwise "no record" would be
            # silently treated as zero consumption -- exactly the T8 failure.
            if ee.status in {ExecStatus.UNCERTAIN.value, ExecStatus.PARTIAL.value}:
                results.append(_v(Verdict.INCOMPLETE_EXECUTION_STATUS, ee.event_id, scheme,
                                  "witness execution status not finalized/settleable; "
                                  "must NOT settle as zero",
                                  witness_status=ee.status))
            elif ee.status == ExecStatus.REGISTERED.value and ue is not None:
                # REGISTERED is intent only; a usage claim exists but the witness
                # never advanced past REGISTERED -> inconsistent state.
                results.append(_v(Verdict.INCOMPLETE_EXECUTION_STATUS, ee.event_id, scheme,
                                  "usage claimed but witness never advanced beyond REGISTERED",
                                  witness_status=ee.status))

            if ue is None:
                results.append(_v(Verdict.MISSING_USAGE_EVENT, ee.event_id, scheme,
                                  "witness registered event has no accepted usage record",
                                  sequence_no=ee.sequence_no, witness_status=ee.status))
                continue
            # linkage: run/operation/attempt must all match
            if (ue.run_id != ee.run_id or ue.operation_id != ee.operation_id
                    or ue.attempt_id != ee.attempt_id):
                results.append(_v(Verdict.INVALID_EVENT_LINKAGE, ee.event_id, scheme,
                                  "usage fields do not match witness registration",
                                  witness=(ee.run_id, ee.operation_id, ee.attempt_id),
                                  usage=(ue.run_id, ue.operation_id, ue.attempt_id)))

        # usage events with no witness registration
        for event_id, ue in accepted_usage.items():
            if event_id not in by_event:
                results.append(_v(Verdict.UNKNOWN_EVENT, event_id, scheme,
                                  "usage event has no witness registration"))

    # --- independent metering cross-check (scheme C only) ---
    if scheme == "C":
        assert ctx.observations is not None and ctx.observer_pubkey is not None
        obs_by_event: dict[str, MeteringObservation] = {}
        for ob in ctx.observations:
            if not _verify_observation_signature(ob, ctx.observer_pubkey):
                results.append(_v(Verdict.INVALID_SIGNATURE, ob.event_id, scheme,
                                  "observation signature invalid"))
                continue
            obs_by_event[ob.event_id] = ob
        for event_id, ue in accepted_usage.items():
            ob = obs_by_event.get(event_id)
            if ob is None:
                results.append(_v(Verdict.MISSING_USAGE_EVENT, event_id, scheme,
                                  "no independent observation for accepted usage"))
                continue
            if ob.unit != ue.unit:
                results.append(_v(Verdict.USAGE_MISMATCH, event_id, scheme,
                                  "unit mismatch between claim and observation",
                                  claimed_unit=ue.unit, observed_unit=ob.unit))
                continue
            if ob.observed_usage != ue.usage:
                results.append(_v(Verdict.USAGE_MISMATCH, event_id, scheme,
                                  "service-declared usage != independent observed usage",
                                  claimed_usage=ue.usage, observed_usage=ob.observed_usage))
        # observation for an event that has no accepted usage
        for event_id in obs_by_event:
            if event_id not in accepted_usage:
                results.append(_v(Verdict.UNKNOWN_EVENT, event_id, scheme,
                                  "observation exists but no accepted usage event"))

    return results


def has_finding(results: Iterable[VerificationResult], verdict: Verdict) -> bool:
    return any(r.verdict == verdict.value for r in results)


def charged_total(results: Iterable[VerificationResult], ctx: VerifyContext) -> int:
    """Amount that would be billed under a scheme.

    Billing rule (same event_id):
      - first signature-valid record is the candidate charge;
      - identical duplicate -> counted ONCE (still billed once);
      - DUPLICATE conflict -> whole event_id rejected (billed zero);
      - INVALID_SIGNATURE / UNKNOWN_EVENT / INVALID_EVENT_LINKAGE /
        INCOMPLETE_EXECUTION_STATUS / USAGE_MISMATCH -> not billed;
      - an event with NO usage record at all contributes nothing, and this is
        NEVER treated as a fabricated "zero consumption" settlement -- it is a
        MISSING_USAGE_EVENT finding (a missing record != zero consumption).
    """
    results = list(results)
    conflict_ids = {
        r.event_id for r in results
        if r.verdict == Verdict.DUPLICATE_USAGE_EVENT.value
        and r.detail.get("duplicate_kind") == "conflict"
    }
    hard_block = {
        Verdict.INVALID_SIGNATURE.value,
        Verdict.UNKNOWN_EVENT.value,
        Verdict.INVALID_EVENT_LINKAGE.value,
        Verdict.INCOMPLETE_EXECUTION_STATUS.value,
        Verdict.USAGE_MISMATCH.value,
    }
    blocked_ids = conflict_ids | {
        r.event_id for r in results if r.verdict in hard_block
    }
    seen: set[str] = set()
    total = 0
    for ev in ctx.usage_events:
        pub = ctx.service_pubkeys.get(ev.source_id)
        if pub is None or not verify_payload(pub, ev.signature, ev.signed_payload()):
            continue
        if ev.event_id in seen:
            continue  # identical duplicate: do not double-charge
        seen.add(ev.event_id)
        if ev.event_id in blocked_ids:
            continue
        total += ev.usage
    return total
