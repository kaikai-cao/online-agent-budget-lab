//! D11.3-B.0 — Poseidon parameter freeze and Halo2 gadget compatibility probe.
//!
//! Scope (deliberately narrow):
//!   - freeze the Poseidon instance, field encoding and domain separation used by
//!     the later D11.3-B.1 state-transition circuit;
//!   - prove that the official `halo2_gadgets::poseidon::Pow5Chip` (0.6.0) is
//!     compatible with the D11.2 baseline `halo2_proofs` 0.4.0;
//!   - prove, with real circuits, that native and in-circuit Poseidon agree for
//!     the three fixed input lengths used by D11.3-A (4, 5 and 7).
//!
//! This crate does **not** implement the budget state machine, the Coordinator,
//! the Executor metering path, or the full state-transition circuit. Those are
//! D11.3-B.1 and later work items.

pub mod poseidon_probe;
pub mod range;
pub mod state_transition;

pub use poseidon_probe::{
    native_poseidon, PoseidonHashCircuit, PoseidonProbeConfig, K_PROBE, RATE, WIDTH,
};
pub use state_transition::{StateTransitionCircuit, StateWitness, INSTANCE_ROWS};

/// Domain-separator for the state commitment `C`.
///
/// ASCII "DSTATE" = 0x44 53 54 41 54 45.
pub const D_STATE: u64 = 0x4453_5441_5445;
/// Domain-separator for the key commitment `K`.
///
/// ASCII "DKEY" = 0x44 4b 45 59.
pub const D_KEY: u64 = 0x444b_4559;
/// Domain-separator for the nullifier `N`.
///
/// ASCII "DNF" = 0x44 4e 46.
pub const D_NF: u64 = 0x444e_46;
