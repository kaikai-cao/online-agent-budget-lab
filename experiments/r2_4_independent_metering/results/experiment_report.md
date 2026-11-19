# R2.4 Phase-1 — Independent Event Witness & Trustworthy Metering

Generated: 2026-11-19T11:37:04.782362+00:00
Seed base: 20261119 · trials/scenario: 10 · total trial records: 80

## Scope boundary (read first)

- An independent event source reveals *missing / deleted / duplicated* metering records and *inconsistent status* for **observed** execution intents.
- It CANNOT learn operations the service performed that were never observed, and CANNOT by itself establish the true resource consumption.
- Detecting under-reporting is NOT proving a metering value real. Only an independent observation (scheme C) offers numeric cross-check, under its own trust assumption.
- No ZKP/Halo2/TEE/Merkle tree/real LLM/MCP. Witness, services and observer use separate SQLite DBs and separate Ed25519 keys; this is logical, not hardware, isolation.

## Schemes

- **A** ordinary signed metering: verify service signature + linkage; direct sum. Detects tamper/duplicate, blind to omission & numeric lies.
- **B** A + independent event witness: additionally detects missing usage, unknown events, linkage mismatch, incomplete status. STILL blind to numeric lies (witness registers intent, not consumption).
- **C** B + independent metering observation: additionally detects USAGE_MISMATCH between service claim and observed value.

## Verdict taxonomy (never collapsed to a single 'INVALID')

ACCEPTED · MISSING_USAGE_EVENT · DUPLICATE_USAGE_EVENT · INVALID_SIGNATURE · USAGE_MISMATCH · INCOMPLETE_EXECUTION_STATUS · UNKNOWN_EVENT · INVALID_EVENT_LINKAGE

## Capability & metrics (detection / false-positive / false-negative)

| Scenario | Scheme | Expected verdicts | Detection | FP rate | FN rate |
| --- | --- | --- | --- | --- | --- |
| T1 | A | — (blind/normal) | N/A | 0% | N/A |
| T1 | B | — (blind/normal) | N/A | 0% | N/A |
| T1 | C | — (blind/normal) | N/A | 0% | N/A |
| T2 | A | — (blind/normal) | N/A | 0% | N/A |
| T2 | B | MISSING_USAGE_EVENT | 100% | 0% | 0% |
| T2 | C | MISSING_USAGE_EVENT | 100% | 0% | 0% |
| T3 | A | — (blind/normal) | N/A | 0% | N/A |
| T3 | B | MISSING_USAGE_EVENT | 100% | 0% | 0% |
| T3 | C | MISSING_USAGE_EVENT | 100% | 0% | 0% |
| T4 | A | INVALID_SIGNATURE | 100% | 0% | 0% |
| T4 | B | INVALID_SIGNATURE | 100% | 0% | 0% |
| T4 | C | INVALID_SIGNATURE | 100% | 0% | 0% |
| T5 | A | DUPLICATE_USAGE_EVENT | 100% | 0% | 0% |
| T5 | B | DUPLICATE_USAGE_EVENT | 100% | 0% | 0% |
| T5 | C | DUPLICATE_USAGE_EVENT | 100% | 0% | 0% |
| T6 | A | — (blind/normal) | N/A | 0% | N/A |
| T6 | B | — (blind/normal) | N/A | 0% | N/A |
| T6 | C | — (blind/normal) | N/A | 0% | N/A |
| T7 | A | — (blind/normal) | N/A | 0% | N/A |
| T7 | B | — (blind/normal) | N/A | 0% | N/A |
| T7 | C | USAGE_MISMATCH | 100% | 0% | 0% |
| T8 | A | — (blind/normal) | N/A | 0% | N/A |
| T8 | B | INCOMPLETE_EXECUTION_STATUS | 100% | 0% | 0% |
| T8 | C | INCOMPLETE_EXECUTION_STATUS | 100% | 0% | 0% |

Notes on rates:
- `detection`/`FN` are `N/A` when a scheme is *expected to be blind* (no expected verdict): that is by design, not a missing measurement.
- FP = a verdict appeared that the scenario's `absent` matrix says must not appear (e.g. A falsely 'detecting' an omission it cannot see).
- T6 is a normal multi-attempt case: any DUPLICATE/INCOMPLETE verdict would be a false positive; the matrix confirms none.

## Flagship control — T7

- Scheme A detects numeric lie: **False**
- Scheme B detects numeric lie: **False**
- Scheme C detects numeric lie in all 10 trials: **True**
- Signature authenticates origin+integrity; only independent observation can cross-check a numeric value. B (witness registers intent) alone does NOT prove metering truth.

## Entering phase 2? (gating conditions from the task package)

1. B stably detects omissions/status that A cannot: **True and measured detection 100%**. See T2/T3 rows.
2. C stably detects numeric lies that A/B cannot: **True**. See T7.
3. Each gain maps to an explicit trust assumption: witness honesty (its own key/DB), observer honesty (its own key/DB), service untrusted.
4. No self-reported duplicate treated as independent: service claim and observer observation are separate keys/DBs/signers by construction.

## Residual boundaries

- Witness sees only registered intents and their status transitions; it cannot see unregistered internal service work.
- Service controls what it submits and what value it signs; in A/B its signed false value is accepted as-is.
- Observer is a SIMULATED trusted point; real cloud/network/TEE metering trust is NOT solved.
- Even C cannot detect a lie if the observer is also compromised, or if consumption happens entirely outside both service claim and observer. No exactly-once / global truth claim.
- This is a single-node logical-independence prototype; no cross-host consistency, no performance/stress testing.
