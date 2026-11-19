# R2.4 Phase 2 — Gateway Enforcement vs. Independent Metering Coverage

Isolated discrimination experiment. **No ZKP/Halo2/TEE/Merkle, no real LLM/MCP,
no token/CPU/GPU metering, no billing/payment.** Python stdlib + `cryptography`
Ed25519 + separate SQLite DBs. Nothing here touches Phase-1 `r24` or any frozen
stage.

## Question

What do a mandatory gateway, an independent ingress observer and a witness/
observer evidence set each ADD, in coverage terms, for cross-domain tool calls?
The experiment is built to **allow a NO-GO**: if a simple gateway already covers
the target scenarios, that is reported honestly.

## Four schemes (same physical calls, different architecture)

| Scheme | Composition |
| --- | --- |
| P0 | service self-report (service-signed submissions) |
| P1 | P0 + mandatory enforcement gateway |
| P2 | P1 + independent ingress observer (own DB + own key) |
| P3 | P2 + witness-registered expected calls |

P1 is a REAL gateway: the service entrance authenticates a gateway-SIGNED
receipt with the gateway public key; a direct/bypass call is rejected and never
executes. P2's observer has its own DB and key; the service has no handle to it.

## Five scenarios

- T1 normal call (baseline)
- T2 bypass gateway (P1 rejects; rejected != executed)
- T3 service executed but did not report (forward receipt != execution)
- T4 retry (two distinct attempts) + duplicate transmission
- T5 observer failure (evidence lost -> UNCERTAIN, not "complete")

## Four metrics (never merged)

- execution coverage — ground-truth executed calls with an evidence anchor
- missing-report detection — suppressed reports correctly flagged
- duplicate-metering error — double-billed or wrongly-merged calls
- uncertain-state correctness — UNCERTAIN on lost observation

## Ground-truth isolation

`service_executed` is recorded by the controller only. Verifier functions accept
only signed observable records (`ObservableEvidence`) and can no more read ground
truth than call a function that has no such parameter. `assert_no_ground_truth`
and a dedicated test enforce this. The four metrics are computed by the runner
by joining verifier verdicts to ground truth — the verifier never scores itself.

## Layout

```
configs/experiment.yaml   seed, matrix, expected results (pre-registered hypothesis)
src/r24p2/
  models.py              records, canonical signing, isolation guard
  gateway.py             P1 mandatory gateway (signed forward receipts)
  service.py             gateway-authenticated service entrance
  ingress_observer.py    P2 independent ingress observation
  witness.py             P3 expected-call registration
  ground_truth.py        controller-only authoritative log
  verifier.py            P0-P3 views, observable-evidence only
  scenarios.py           T1-T5, four isolated worlds per trial
scripts/run_experiments.py  50-trial runner + four metrics + report
tests/                   five scenario/mechanism test files
results/
  raw_results.jsonl      50 rows (5 scenarios x 10 trials), full evidence
  summary.json           four metrics + expectation conformance
  experiment_report.md   facts, GO/NO-GO evidence, honesty boundaries
```

## Reproduce

```bash
../../.venv/Scripts/python -m unittest discover -s tests -v
../../.venv/Scripts/python scripts/run_experiments.py
```

Fixed seed base `20261120`, 10 trials/scenario. The 50 trials validate
reproducibility and scenario conformance, NOT statistical security.

## Prior art (not re-packaged as novelty)

- IETF IoA Usage Accounting draft: tool-call events, coverage boundary,
  expected-event sets, retransmission vs execution attempt.
- OWASP MCP secure-development guide: tool-call identity, request ID, parameter
  metadata, approval, policy decision, audit log. A plain MCP call log is not a
  sufficient contribution.
