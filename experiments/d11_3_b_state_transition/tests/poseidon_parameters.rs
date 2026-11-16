//! D11.3-B.0 acceptance tests.
//!
//! 1. `halo2_gadgets 0.6.0` Poseidon gadget compiles and runs against
//!    `halo2_proofs 0.4.0`.
//! 2. Native and in-circuit hashes agree for fixed lengths 4, 5 and 7.
//! 3. A 7-word hash completes a real keygen -> prove -> verify round trip.
//! 4. Deterministic input/output vectors are pinned so that a dependency
//!    upgrade cannot silently change the commitment function.

use d11_3_b_state_transition::{
    native_poseidon, poseidon_probe::PoseidonHashCircuit, D_KEY, D_NF, D_STATE, K_PROBE,
};
use halo2_proofs::{
    arithmetic::Field,
    dev::MockProver,
    pasta::{EqAffine, Fp},
    plonk::{self, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};

/// Deterministic protocol-shaped inputs (no RNG), matching D11.3-A field
/// encodings: [domain, nf_secret, budget_id, period_id, ...].
const NF_SECRET: u64 = 11;
const BUDGET_ID: u64 = 101;
const PERIOD_ID: u64 = 7;
const QUOTA: u64 = 1000;
const SPENT: u64 = 30;
const BLIND: u64 = 5;

fn key_message() -> [Fp; 4] {
    [
        Fp::from(D_KEY),
        Fp::from(NF_SECRET),
        Fp::from(BUDGET_ID),
        Fp::from(PERIOD_ID),
    ]
}

fn state_message(k: Fp) -> [Fp; 7] {
    [
        Fp::from(D_STATE),
        Fp::from(BUDGET_ID),
        Fp::from(PERIOD_ID),
        Fp::from(QUOTA),
        Fp::from(SPENT),
        Fp::from(BLIND),
        k,
    ]
}

fn nullifier_message(c_old: Fp) -> [Fp; 5] {
    [
        Fp::from(D_NF),
        Fp::from(NF_SECRET),
        Fp::from(BUDGET_ID),
        Fp::from(PERIOD_ID),
        c_old,
    ]
}

/// Pinned deterministic vectors. Values are the canonical big-endian hex
/// representation printed by `pallas::Base`'s `Debug` impl (32-byte field
/// elements). Any dependency upgrade that changes these hashes fails here.
///
/// Inputs are fixed in `key_message` / `state_message` / `nullifier_message`
/// above; see `docs/D11.3_B_POSEIDON_PARAMETER_FREEZE.md`.
#[test]
fn deterministic_test_vectors() {
    let k = native_poseidon(key_message());
    let c = native_poseidon(state_message(k));
    let n = native_poseidon(nullifier_message(c));

    assert_eq!(
        format!("{k:?}"),
        "0x1fc476e969adea420c833e16e9c12cfb5b4e0dbc94f6f1c1dbe0d595bd45047b"
    );
    assert_eq!(
        format!("{c:?}"),
        "0x2a7b5ddbf856ba032f1caab86922132fcc533859cf3ed334c23e0af659ac8e7b"
    );
    assert_eq!(
        format!("{n:?}"),
        "0x1f6484ba7182ebd3fe58fc3db0fdff30c2c1e4f2f463aaa6de3653e51cb405b3"
    );
}

#[test]
fn domain_separators_are_distinct() {
    assert_ne!(D_STATE, D_KEY);
    assert_ne!(D_STATE, D_NF);
    assert_ne!(D_KEY, D_NF);
    assert_eq!(Fp::from(D_STATE), Fp::from(0x4453_5441_5445u64));
    assert_eq!(Fp::from(D_KEY), Fp::from(0x444b_4559u64));
    assert_eq!(Fp::from(D_NF), Fp::from(0x444e_46u64));
}

/// Helper: run a MockProver circuit with the native hash as public instance,
/// and confirm that a wrong instance is rejected.
fn circuit_matches_native<const L: usize>(message: [Fp; L]) {
    let expected = native_poseidon(message);
    let circuit = PoseidonHashCircuit::<L> { message };

    let prover = MockProver::run(K_PROBE, &circuit, vec![vec![expected]])
        .expect("MockProver::run must succeed with a well-formed circuit");
    assert_eq!(
        prover.verify(),
        Ok(()),
        "circuit hash != native hash (L={L})"
    );

    // Wrong public output must not verify: this proves the output cell is
    // genuinely constrained, not merely assigned as a private witness.
    let wrong = expected + Fp::ONE;
    let prover = MockProver::run(K_PROBE, &circuit, vec![vec![wrong]])
        .expect("MockProver::run must succeed with a well-formed circuit");
    assert!(
        prover.verify().is_err(),
        "a wrong public output must be rejected (L={L})"
    );
}

#[test]
fn circuit_hash_matches_native_key_commitment_4_inputs() {
    circuit_matches_native(key_message());
}

#[test]
fn circuit_hash_matches_native_nullifier_5_inputs() {
    let k = native_poseidon(key_message());
    let c = native_poseidon(state_message(k));
    circuit_matches_native(nullifier_message(c));
}

#[test]
fn circuit_hash_matches_native_state_commitment_7_inputs() {
    let k = native_poseidon(key_message());
    circuit_matches_native(state_message(k));
}

/// Real proof/verify round trip for the 7-word state commitment. Uses the same
/// transcript and RNG setup as the D11.2 acceptance tests.
#[test]
fn real_proof_verify_7_inputs() {
    let k = native_poseidon(key_message());
    let message = state_message(k);
    let expected = native_poseidon(message);

    let circuit = PoseidonHashCircuit::<7> { message };

    let params = Params::new(K_PROBE);
    let vk = plonk::keygen_vk(&params, &circuit).expect("keygen_vk");
    let pk = plonk::keygen_pk(&params, vk, &circuit).expect("keygen_pk");

    let instances = vec![expected];
    let instance_slices: Vec<&[Fp]> = vec![instances.as_slice()];
    let instance_refs: Vec<&[&[Fp]]> = vec![instance_slices.as_slice()];

    let mut transcript = Blake2bWrite::<_, EqAffine, _>::init(vec![]);
    plonk::create_proof(
        &params,
        &pk,
        &[circuit],
        &instance_refs,
        &mut UnwrapErr(SysRng),
        &mut transcript,
    )
    .expect("create_proof");
    let proof = transcript.finalize();

    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(
        plonk::verify_proof(
            &params,
            pk.get_vk(),
            strategy,
            &instance_refs,
            &mut transcript
        )
        .is_ok(),
        "honest proof with correct public input must verify"
    );

    // Tampered public input must fail verification.
    let wrong_instances = vec![expected + Fp::ONE];
    let wrong_slices: Vec<&[Fp]> = vec![wrong_instances.as_slice()];
    let wrong_refs: Vec<&[&[Fp]]> = vec![wrong_slices.as_slice()];
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    assert!(
        plonk::verify_proof(&params, pk.get_vk(), strategy, &wrong_refs, &mut transcript).is_err(),
        "proof must not verify against a tampered public input"
    );
}
