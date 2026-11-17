//! D11.3-C — experimental off-chain Coordinator for the D11.3 private budget
//! state model.
//!
//! Scope: issuer-signed initial registration, real Halo2 proof verification
//! (reusing the D11.3-B.1 circuit), SQLite state/nullifier persistence, and an
//! atomic compare-and-swap commit. This crate deliberately does **not** touch
//! the D9 production Coordinator, Executor metering, or the D10 authorization
//! chain.

use ff::PrimeField;
use halo2_proofs::pasta::Fp;

pub mod coordinator;
pub mod e1_encoding;
pub mod proof_verifier;
pub mod registration;
pub mod state_store;

/// Public instance row count of the reused B.1 circuit.
pub use coordinator::CoordinatorError;
pub use d11_3_b_state_transition::INSTANCE_ROWS;

/// Canonical field-element byte width (Pallas base field).
pub const FIELD_BYTES: usize = 32;
/// Largest value admitted by the B.1 uint32 range constraints.
pub const MAX_UINT32: u64 = (1u64 << 32) - 1;

/// Canonical, fixed-width little-endian field encoding used by registration
/// signatures and by SQLite text columns. `Fp::to_repr()` is the canonical
/// representation; no ad-hoc decimal or string encoding is used.
pub fn fp_to_bytes(value: &Fp) -> [u8; FIELD_BYTES] {
    let repr = value.to_repr();
    let mut out = [0u8; FIELD_BYTES];
    out.copy_from_slice(repr.as_ref());
    out
}

/// Decode a canonical byte representation. `from_repr` rejects non-canonical
/// (out-of-field) encodings, so this also enforces field validity.
pub fn fp_from_bytes(bytes: &[u8; FIELD_BYTES]) -> Option<Fp> {
    let mut repr = <Fp as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(bytes);
    Fp::from_repr(repr).into()
}

/// Hex form of [`fp_to_bytes`], used for human-inspectable SQLite columns.
pub fn fp_to_hex(value: &Fp) -> String {
    fp_to_bytes(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Inverse of [`fp_to_hex`]; returns `None` for wrong length, non-hex input or
/// a non-canonical field encoding.
pub fn fp_from_hex(text: &str) -> Option<Fp> {
    if text.len() != FIELD_BYTES * 2 {
        return None;
    }
    let bytes = (0..FIELD_BYTES).map(|i| {
        let pair = text.get(i * 2..i * 2 + 2)?;
        u8::from_str_radix(pair, 16).ok()
    });
    let mut out = [0u8; FIELD_BYTES];
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = byte?;
    }
    fp_from_bytes(&out)
}

/// Recover a `u64` from a field element only when all upper bytes are zero.
/// Used to enforce the B.1 uint32 domain at registration and public-input
/// parsing instead of silently reducing a larger integer mod p.
pub fn fp_to_u64_checked(value: &Fp) -> Option<u64> {
    let bytes = fp_to_bytes(value);
    if bytes[8..].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")))
}
