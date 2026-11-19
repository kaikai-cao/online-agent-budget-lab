# R2.4 Phase-1 — Independent Event Witness & Trustworthy Metering

Isolated prototype experiment. **No ZKP/Halo2/TEE/Merkle tree, no real LLM/MCP.**
Uses Python stdlib + `cryptography` Ed25519 + three separate SQLite databases.

## What this experiment answers

> With an untrusted Agent coordinator and untrusted tool services, can an
> event-registration mechanism independent of both detect event omission,
> metering deletion, duplicate reporting and inconsistent execution status?

It deliberately separates two claims that must NOT be conflated:

1. **Event completeness / fault detection** — can we find "an observed request
   has no matching metering record", deletion, duplication, status mismatch?
2. **Metering truthfulness** — can we find a service that signed a false value?

Detecting (1) does **not** prove (2). Only scheme C's independent observation
can cross-check a number, and only under the observer's own trust assumption.

## The three schemes

| Scheme | Composition | What it can detect |
| --- | --- | --- |
| A | service-signed metering + direct sum | tampering, duplicate; **blind** to omission & numeric lies |
| B | A + independent event witness | + missing usage, unknown events, linkage mismatch, incomplete status; **still blind** to numeric lies |
| C | B + independent metering observation | + USAGE_MISMATCH (claim vs observed) |

## Three structural independencies (logical, NOT hardware)

1. Witness / service / observer each own a **separate SQLite DB**.
2. Each owns a **separate Ed25519 key** (4 disjoint keys: witness, svc A, svc B, observer).
3. Tool services are never given a handle to witness/observer DBs or keys, so
   they cannot modify a registered event. Keys are derived deterministically
   from the fixed seed; no private key is written to disk.

## Layout

```
src/r24/
  models.py        records, enums, canonical encoding + Ed25519 helpers
  witness.py       independent event registration service
  tool_service.py  two simulated services (honest + attack helpers)
  metering.py      independent metering observation module
  verifier.py      schemes A/B/C, 8 fine-grained verdicts, billing rules
  scenarios.py     T1-T8 scenarios, deterministic seeds, >=10 trials
scripts/
  run_experiments.py   full matrix runner + artifact generation
tests/               one file per scenario family + state machine (18 tests)
results/
  raw_results.jsonl    80 rows (8 scenarios x 10 trials), full evidence
  summary.json         capability matrix / detection / FP / FN / control
  experiment_report.md human report with honesty boundaries
  typical_cases.json   full T2/T6/T7 trial-0 event records
```

## Reproduce

From this directory, using the repo venv:

```bash
# unit tests (18)
../../.venv/Scripts/python -m unittest discover -s tests -v

# full experiment matrix -> rewrites results/*
../../.venv/Scripts/python scripts/run_experiments.py
```

On non-Windows use `.venv/bin/python`. Fixed seed base `20261119`, 10 trials
per scenario, so results are reproducible.

## Scenario → expected detection (capability matrix)

| ID | Scenario | A | B | C |
| --- | --- | --- | --- | --- |
| T1 | normal (300+200=500) | accept | accept | accept |
| T2 | service under-reporting (never submits) | blind | MISSING_USAGE_EVENT | MISSING_USAGE_EVENT |
| T3 | coordinator drops record from aggregation input (service DB keeps it) | blind | MISSING_USAGE_EVENT | MISSING_USAGE_EVENT |
| T4 | tamper signed value | INVALID_SIGNATURE | INVALID_SIGNATURE | INVALID_SIGNATURE |
| T5 | duplicate report | DUPLICATE (count once / conflict reject) | same | same |
| T6 | two attempts 30+20 | accept (50) | accept (50) | accept (50) |
| T7 | report 100, actual 250 | **blind** | **blind** | **USAGE_MISMATCH** |
| T8 | stuck UNCERTAIN | blind | INCOMPLETE, not zero-settled | INCOMPLETE, not zero-settled |

T7 is the flagship control: a witness that registers *intent* cannot prove a
numeric value. Only an independent *observation* can cross-check it.

## Enforced state machine (not just documented)

`EventWitness.advance_status()` enforces `LEGAL_TRANSITIONS`: illegal jumps and
undefined status strings are rejected and the DB row is left byte-identical.
FINALIZED is terminal; UNCERTAIN can only reach FINALIZED via CORRECTED, so an
uncertain event cannot silently settle as zero. `tests/test_state_machine.py`
covers illegal jumps (incl. REGISTERED->FINALIZED, DISPATCHED->FINALIZED),
repeated terminal transition, uncertain-bypass, undefined states and no-change-
on-reject.

## How to read the 100% / 0% numbers

They are the **expected-behaviour conformance rate** over 8 pre-constructed
scenarios x 10 deterministic repetitions (verdict set matched the declared
capability matrix). They are NOT a real attack detection rate, NOT detection of
unknown attacks, NOT a statistically meaningful false-positive rate, and NOT a
production guarantee. The 80 records are repetitions of 8 known scenario types,
not 80 independent real attacks.

## Boundaries (do not overstate)

- Witness sees only registered intents and their status transitions; it cannot
  see internal service work that was never registered.
- Service controls which rows it submits and which value it signs. In A/B a
  signed false value is accepted as-is.
- Observer is a **simulated** trusted point — this does not solve real cloud /
  network / TEE metering trust. Even C cannot detect a lie if the observer is
  compromised, or if consumption is outside both claim and observation.
- No exactly-once, no global truth, no cross-host consistency, no performance
  or stress testing. This validates a security *mechanism*, not a production
  metering system.
