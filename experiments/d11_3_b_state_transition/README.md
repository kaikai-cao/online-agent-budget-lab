# D11.3-B.0 — Poseidon parameter freeze and Halo2 compatibility probe

This crate freezes the Poseidon parameters for D11.3-B and verifies that the
official gadget is compatible with the D11.2 Halo2 baseline **before** the full
state-transition circuit is written.

## Scope

In scope:

- freeze the Poseidon instance, field encoding and domain separators;
- verify `halo2_gadgets 0.6.0` + `halo2_proofs 0.4.0` actually compile and run;
- prove native and in-circuit hashes agree for fixed lengths 4, 5 and 7;
- complete one real `keygen -> prove -> verify` round trip for the 7-word hash;
- pin deterministic test vectors.

Out of scope (D11.3-B.1 and later): the budget state machine, Coordinator,
Executor metering, the full state-transition circuit, and any production code.

## Layout

- `src/poseidon_probe.rs` — generic `PoseidonHashCircuit<L>` that binds
  `Poseidon_L(message)` to `instance[0]` via `Pow5Chip`.
- `tests/poseidon_parameters.rs` — native/circuit equality for L=4,5,7 and
  the real proof/verify test.

## Acceptance

```powershell
cargo check --manifest-path experiments/d11_3_b_state_transition/Cargo.toml
cargo test --manifest-path experiments/d11_3_b_state_transition/Cargo.toml -- --nocapture
cargo fmt --manifest-path experiments/d11_3_b_state_transition/Cargo.toml -- --check
```
