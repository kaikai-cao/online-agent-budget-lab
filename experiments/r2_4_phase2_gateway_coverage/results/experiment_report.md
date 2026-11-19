# R2.4 Phase 2 — Gateway Enforcement vs. Independent Metering Coverage

Generated: 2026-11-19T12:27:59.986666+00:00
Seed base: 20261120 · trials/scenario: 10 · raw records: 50

## Purpose (discrimination, NOT a proof)

This experiment asks what mandatory gateway enforcement, ingress observation and witness/observer evidence each ADD in coverage terms. It is designed to allow a NO-GO result: if a simple enforcement gateway already covers the target scenarios, that is reported honestly rather than packaging complexity as research value.

## Scope boundaries

- IN: tool-call counts, ingress receipt, call linkage, uncertain-state on missing observation.
- OUT: token/CPU/GPU metering, cross-domain delegation, real TEE/attestation, Halo2/ZKP, pricing/billing/payment. See configs/experiment.yaml.

## Schemes

- **P0** — service self-report (service-signed submissions only)
- **P1** — P0 + mandatory enforcement gateway (entrance authenticates gateway-signed receipts)
- **P2** — P1 + independent ingress observer (own DB + own key)
- **P3** — P2 + witness-registered expected calls

## Isolation & honesty guards

- P1 is a REAL mandatory gateway: the service entrance authenticates a gateway-SIGNED receipt with the gateway public key; a direct/bypass call is rejected and never executes (test_gateway_enforcement.py).
- `service_executed` (ground truth) is recorded by the controller only and is NEVER a verifier input; verifier functions accept only signed observable records, and assert_no_ground_truth enforces it (test_missing_report.py).
- Gateway FORWARD receipt proves traversal, NOT execution: a forwarded-but-unreported call is MISSING_EVIDENCE, never COVERED.
- service_acceptance != service_execution; a recorded row != a complete/true record; an observer row != observation of all paths.

## Four metrics (kept separate)

| Scheme | Execution coverage | Missing-report detection | Duplicate-metering errors | Uncertain-state correctness |
| --- | --- | --- | --- | --- |
| P0 | 40/50 = 80% | 0/10 = 0% | 10 / 10 trials | 0/10 = 0% |
| P1 | 40/40 = 100% | 10/10 = 100% | 0 / 10 trials | 0/10 = 0% |
| P2 | 40/40 = 100% | 10/10 = 100% | 0 / 10 trials | 10/10 = 100% |
| P3 | 40/40 = 100% | 10/10 = 100% | 0 / 10 trials | 10/10 = 100% |

Metric definitions:
- `execution_coverage`: of ground-truth EXECUTED logical calls, fraction that have an observable evidence anchor (any non-NO_EVIDENCE verdict) under the scheme; joined by logical_call_id so P0's missing attempt tracking is not conflated with coverage; rejected bypass requests are excluded from the denominator
- `missing_report_detection`: of deliberately suppressed reports (T3), fraction the scheme flags as MISSING_EVIDENCE
- `duplicate_metering_error`: count of calls where same execution is billed more than once OR distinct attempts merged into one bill
- `uncertain_state_correctness`: of T5 trials (observation lost), fraction the scheme returns UNCERTAIN instead of COVERED

## Pre-registered expectation conformance (50 trials)

Expected matrix is a hypothesis, NOT an obtained result.

| Scenario | Scheme | Expected | Conform / total |
| --- | --- | --- | --- |
| T1 | P0 | COVERED | 10/10 |
| T1 | P1 | COVERED | 10/10 |
| T1 | P2 | COVERED | 10/10 |
| T1 | P3 | COVERED | 10/10 |
| T2 | P0 | COVERED | 10/10 |
| T2 | P1 | (none) | 10/10 |
| T2 | P2 | BYPASS_DETECTED | 10/10 |
| T2 | P3 | BYPASS_DETECTED | 10/10 |
| T3 | P0 | (none) | 10/10 |
| T3 | P1 | MISSING_EVIDENCE | 10/10 |
| T3 | P2 | MISSING_EVIDENCE | 10/10 |
| T3 | P3 | MISSING_EVIDENCE | 10/10 |
| T4 | P0 | DUPLICATE_IGNORED | 10/10 |
| T4 | P1 | COVERED, DUPLICATE_IGNORED | 10/10 |
| T4 | P2 | COVERED, DUPLICATE_IGNORED | 10/10 |
| T4 | P3 | COVERED, DUPLICATE_IGNORED | 10/10 |
| T5 | P0 | COVERED | 10/10 |
| T5 | P1 | COVERED | 10/10 |
| T5 | P2 | UNCERTAIN | 10/10 |
| T5 | P3 | UNCERTAIN | 10/10 |

## Key scenario facts

- T2 bypass: P1 rejects at the entrance (service_executed=False), so the bypassed request is NOT counted as a successful execution. P2/P3 additionally observe the unauthenticated entrance request (BYPASS_DETECTED). P0 has no gateway and cannot see the bypass.
- T3 no-report: the service executed but submitted nothing. P1 flags the gateway-forward/evidence gap; it cannot prove execution. P2/P3 have independent ingress corroboration. P0 detects nothing (no anchor).
- T4 retry/dup: two DISTINCT attempts plus one duplicate transmission. P0 merges the attempts (one bill for two executions = duplicate-metering error); P1-P3 key by attempt_id and keep them distinct.
- T5 observer failure: service executed and reported, but independent ingress evidence was lost. P2/P3 return UNCERTAIN; P0/P1 still say COVERED because their evidence stack contains no independent observation.

## GO / NO-GO — evidence, not a pre-decided winner

Facts that bear on each criterion (read the four-metric table above):

- *Does the mandatory gateway (P1) already cover the target scenarios?* P1 detects the T3 evidence gap and rejects T2 bypass, but in T5 it still reports COVERED with no independent observation. Whether that residual is 'worth researching' is a judgment; the data shows what P1 can and cannot see.
- *Does P2/P3 add a property beyond P1?* T5 is the discriminator: P2/P3 return UNCERTAIN where P1 reports COVERED; T3 adds independent ingress corroboration. This property comes with an explicit extra trust assumption (an independent observer), which must be weighed — not assumed away.
- *Is the extra property 'just another log'?* T2/T5 show the observer's evidence changes the verdict (bypass detection / uncertainty), not merely adds a row — but the observer independence is itself a trust assumption, so this is NOT claimed as a mechanism-only gain.
- *Could a simple access-control + signed-log + state check reproduce it?* P1 is essentially that baseline. The observed residual (T5) is exactly the question to decide; this experiment reports it, it does not resolve the architectural choice.

Decision rule from the task package is applied only after independent review of these artifacts. P3 is NOT presumed strongest.

## Prior art (do not re-package as novelty)

- IETF IoA Usage Accounting draft: tool-call events, coverage boundary, expected-event sets, record retransmission vs execution attempt — not re-packaged as novelty
- OWASP MCP secure-development guide: tool-call identity, request ID, parameter metadata, approval, policy decision, audit log — adding a plain MCP call log is not a sufficient contribution

## Residual boundaries

- 50 trials validate reproducibility and scenario conformance, NOT statistical security; N=10 per scenario, fixed seeds.
- No real LLM/DeepSeek/MCP, no real TEE/remote attestation, no ZKP/Halo2, no cross-host consistency, no performance testing.
- This is a single-process logical prototype; independence is by separate DBs/keys, NOT hardware isolation or cross-organization trust.
- No exactly-once / global-truth claim; evidence coverage != execution truth.
