//! D11.2 — Halo2 minimal budget constraint circuit.
//!
//! A standalone Rust experiment that implements the D11.1 integer relation
//! `u + c + s = Q` (equivalently `u + c <= Q`) as a real Halo2 0.4.0 circuit,
//! with 32-bit range constraints on Q, c, u, s and nonzero checks on Q and c.
//!
//! This crate is intentionally independent of the Python production code in
//! `src/online_budget/`. It implements no state commitments, Poseidon,
//! nullifiers, credentials or coordinator logic (those are later stages).

pub mod quota_circuit;

pub use quota_circuit::{QuotaCircuit, BITS, K};
