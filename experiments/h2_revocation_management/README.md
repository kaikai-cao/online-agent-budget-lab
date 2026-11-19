# H2.1 — Revocation snapshot mechanism (implementation + correctness gates)

H2.1 implements the mechanisms frozen in `docs/H2_REVOCATION_DESIGN.md` (H2.0.2,
commit `5b7da43`) and `docs/H2_EXPERIMENT_PROTOCOL.md`. It adds a runnable
B2/C0/C1/C2 comparison with signed, versioned revocation snapshots, a persisted
high-water version (HWM), first-trust bootstrap, an injected logical clock, and
the M01–M15 runner. **No H1 source, H1 test, H1 result, or frozen artifact is
modified.** This is a mechanism-feasibility prototype, not a production system.

## What is implemented

| File | Role |
|---|---|
| `h2_snapshot.py` | Snapshot format (`h2-revocation-snapshot-v1`), canonical Ed25519 signing/verification using only pre-configured `trusted_keys`, cumulative de-duplicated sorted `revoked_jtis`, pure candidate validation with the six frozen rejection codes. Never mutates state. |
| `h2_snapshot_state.py` | SQLite-persisted `{HWM, cached_snapshot, cached_digest, initialized, last_refresh_local}`. Tri-state recovery S0/S1/S2 (design §5.5): only S0 may bootstrap; S2 fails closed with `SNAPSHOT_STATE_UNAVAILABLE` and never auto-reboots. HWM + cache + digest commit in ONE transaction. |
| `h2_executor.py` | Four execution paths (B2 online TLS / C0 / C1 short TTL / C2 snapshot) sharing one `ActionRequest`, digest, jti, trust anchor, Sink and injected clock. C2 pre-exec refresh decision (§5.3), revocation check (§6.2), max-one-attempt refresh with no timer reset on failure, B2 query→consume barrier for M15. Real TCP+TLS + pinned server-certificate fingerprint for B2 and for the snapshot distribution channel. |
| `run_experiment.py` | M01–M15 matrix (M07a/b/c/d) with the protocol §5 unified fields; `--smoke` (callability, 1 trial/cell) and `--full` (formal N=10, H2.2 only). `expected_outcome` is assertion-only; all outcomes/reasons/effects are observed. |
| `tests/test_h2_revocation_management.py` | H2-a…H2-g correctness gates (23 tests). |

Placeholder: `results/run-001/` is created only by `--full` in H2.2. **H2.1 does
not run the formal matrix and does not commit any experiment result.**

## Boundaries (must hold in every report)

- C2 is a **state-distribution mechanism**, not global immediate revocation and
  not exactly-once. Old-snapshot unexpired + unlisted-jti execution is the
  documented path-B risk window, **not** `false_allow`.
- B2's revocation check linearizes at query response; query→consume TOCTOU is a
  known boundary (M15), **not** a defect and not "instant rejection".
- One-time consumption is scoped to the single executor-local SQLite Sink; no
  cross-executor / third-party exactly-once is implied.
- `W_risk`/`D_prop`/`age` use ONLY the injected logical clock (seconds).
  `perf_counter` values (`refresh_latency_ms`/`snapshot_verify_ms`/etc.) are
  cost metrics and are never added into a window value.
- `1/R` is a refresh-success target, not an upper bound on online requests.
  Actual request count comes from per-trial counters (`refresh_attempts`).
- Signature validity does not establish freshness at bootstrap; BOOT-ONLINE
  freshness comes from the trusted TLS pull, BOOT-OFFLINE from trusted
  provisioning (an explicit assumption).

## Reproduce (Windows)

```powershell
$env:PYTHONPATH = "src;tests;experiments/h1_authorization_binding;experiments/h2_revocation_management"

# H2 correctness gates (H2-a..g)
.venv/Scripts/python -m unittest tests.test_h2_revocation_management -v

# H1 frozen tests (must stay green)
$env:PYTHONPATH = "src;tests;experiments/h1_authorization_binding"
.venv/Scripts/python -m unittest tests.test_h1_authorization_binding -v

# Runner callability check (no formal result committed)
$env:PYTHONPATH = "src;tests;experiments/h1_authorization_binding;experiments/h2_revocation_management"
.venv/Scripts/python experiments/h2_revocation_management/run_experiment.py --smoke --output-dir <tmpdir>

# H2.2 only: formal N=10 matrix
.venv/Scripts/python experiments/h2_revocation_management/run_experiment.py --full `
  --output-dir experiments/h2_revocation_management/results/run-001
```

## Trust anchors

- Ed25519 `key_id -> public key`, issuer, audience are pre-configured in the
  Executor; keys/certs carried in a request or snapshot are never trusted.
- B2 and the snapshot channel pin the service server-certificate SHA-256
  fingerprint over real localhost TCP+TLS (not HTTPS, not mTLS).
