# D11.3-B — private budget state-transition circuit

B.0 freezes the Poseidon parameters and proves the official gadget works with
the D11.2 Halo2 baseline. B.1 composes those frozen components into the full
state-transition circuit defined by D11.3-A.

## Scope

In scope:

- B.0: Poseidon instance / field encoding / domain separators, gadget
  compatibility, native == circuit hashes for L=4/5/7, real proof/verify,
  pinned test vectors.
- B.1: one circuit enforcing uint32 ranges, the two independent budget
  equations, gadget-derived `K`, both state commitment openings, the Nullifier,
  and the 8-row public instance layout.

Out of scope: Coordinator state machine / CAS storage, registration
authorization, Executor metering, online budget state machine, production code,
and any change to the frozen D11.3-A / D11.3-B.0 documents.

## Circuit relation

Public instance: `[budget_id, period_id, Q, c, C_old, C_new, N, P]`.
`P` occupies row 7 but is not constrained by the circuit — the Coordinator
compares it with `registered_policy[(budget_id, period_id)]`.

Private witnesses: `u_old`, `u_new`, `s`, `r_old`, `r_new`, `nf_secret`, `K`
(where `K` is computed by the Poseidon gadget, never supplied freely).

Enforced gates:

- `x = sum(b_i 2^i)` and `b_i(b_i-1)=0` for `Q, c, u_old, u_new, s`;
- inversion witnesses for `Q != 0` and `c != 0`;
- `u_old + c - u_new = 0` and `u_new + s - Q = 0` (two separate gates);
- `K = Poseidon_4(D_key, nf_secret, budget_id, period_id)`;
- `C_old = Poseidon_7(D_state, budget_id, period_id, Q, u_old, r_old, K)`;
- `C_new = Poseidon_7(D_state, budget_id, period_id, Q, u_new, r_new, K)`;
- `k_new - k_copy = 0` (the same `K` is used by both states);
- `N = Poseidon_5(D_nf, nf_secret, budget_id, period_id, C_old)`.

`k = 10` was determined empirically (`k = 9` gives `NotEnoughRowsAvailable`).

## Layout

- `src/poseidon_probe.rs` — B.0 generic `PoseidonHashCircuit<L>`.
- `src/range.rs` — reusable uint32 range/nonzero constraints.
- `src/state_transition.rs` — B.1 `StateTransitionCircuit` and `StateWitness`.
- `tests/poseidon_parameters.rs` — B.0 tests (6).
- `tests/state_transition.rs` — B.1 tests (20), including T01–T19, uint32
  maximum boundary, pinned deterministic vectors, empirical `k`, and one real
  proof verified against honest and tampered public inputs.

## Acceptance

```powershell
cargo check --manifest-path experiments/d11_3_b_state_transition/Cargo.toml
cargo test --manifest-path experiments/d11_3_b_state_transition/Cargo.toml -- --nocapture
cargo fmt --manifest-path experiments/d11_3_b_state_transition/Cargo.toml -- --check
git diff --check
git status --short
```
