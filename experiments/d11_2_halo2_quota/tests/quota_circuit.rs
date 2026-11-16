//! D11.2 tests: MockProver constraint checks + real proof generation/verification.

use d11_2_halo2_quota::quota_circuit::{QuotaCircuit, K};
use halo2_proofs::{
    dev::MockProver,
    pasta::{EqAffine, Fp},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::rngs::SysRng;
use rand_core::UnwrapErr;

/// Run the MockProver for a (Q, c, u, s) assignment.
/// Returns Ok(()) if all circuit constraints are satisfied.
fn mock_ok(quota: u64, cost: u64, spent_before: u64, slack: u64) -> bool {
    let circuit = QuotaCircuit::new(quota, cost, spent_before, slack);
    let instance = vec![vec![Fp::from(quota), Fp::from(cost)]];
    match MockProver::run(K, &circuit, instance) {
        Ok(prover) => prover.verify().is_ok(),
        Err(_) => false,
    }
}

#[test]
fn t01_normal_within_quota() {
    assert!(mock_ok(100, 20, 60, 20));
}

#[test]
fn t02_exactly_at_cap() {
    assert!(mock_ok(100, 40, 60, 0));
}

#[test]
fn t03_over_cap() {
    // 60 + 41 = 101 > 100: no nonnegative slack fits.
    assert!(!mock_ok(100, 41, 60, 0));
    // Even trying a wrong slack, the equation cannot hold with 32-bit s.
    assert!(!mock_ok(100, 41, 60, 1));
}

#[test]
fn t04_last_unit() {
    assert!(mock_ok(100, 1, 99, 0));
}

#[test]
fn t05_one_over_after_full() {
    assert!(!mock_ok(100, 1, 100, 0));
}

#[test]
fn t06_zero_quota_rejected() {
    // Q = 0 must fail the Q * Q^{-1} = 1 nonzero gate.
    assert!(!mock_ok(0, 1, 0, 0));
}

#[test]
fn t07_zero_cost_rejected() {
    // c = 0 must fail the c * c^{-1} = 1 nonzero gate.
    assert!(!mock_ok(100, 0, 0, 100));
}

#[test]
fn t08_max_uint32_fit() {
    let max = (1u64 << 32) - 1;
    assert!(mock_ok(max, 1, max - 1, 0));
}

#[test]
fn t09_quota_2_pow32_rejected() {
    // Q = 2^32 cannot be represented in the 32-bit decomposition.
    assert!(!mock_ok(1u64 << 32, 1, 0, 0));
}

#[test]
fn t10_cost_2_pow32_rejected() {
    assert!(!mock_ok(100, 1u64 << 32, 0, 0));
}

#[test]
fn t11_spent_2_pow32_rejected() {
    assert!(!mock_ok(100, 20, 1u64 << 32, 0));
}

#[test]
fn t12_slack_2_pow32_rejected() {
    assert!(!mock_ok(100, 20, 60, 1u64 << 32));
}

#[test]
fn t13_wrong_slack_rejected() {
    // 60 + 20 + 19 = 99 != 100.
    assert!(!mock_ok(100, 20, 60, 19));
}

#[test]
fn t14_instance_mismatch_rejected() {
    // The circuit witness binds Q=100,c=20,u=60,s=20, but the public
    // instance claims different Q/c -> instance copy constraint fails.
    let circuit = QuotaCircuit::new(100, 20, 60, 20);
    let bad_instance = vec![vec![Fp::from(101u64), Fp::from(20u64)]];
    let prover = MockProver::run(K, &circuit, bad_instance).expect("run");
    assert!(prover.verify().is_err());
}

/// Generate a proof for a valid assignment, then verify it against the
/// supplied public inputs (Q, c). Returns Ok(()) iff verification succeeds.
fn prove_and_verify(public_q: u64, public_c: u64) -> Result<(), ()> {
    // The witness is fixed: Q=100, c=20, u=60, s=20.
    let circuit = QuotaCircuit::new(100, 20, 60, 20);

    let params: Params<EqAffine> = Params::new(K);
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk");

    // Note: u and s are NEVER placed in the instance. Only [Q, c] are public.
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&[&[Fp::from(100u64), Fp::from(20u64)]]],
        UnwrapErr(SysRng),
        &mut transcript,
    )
    .expect("create_proof");
    let proof = transcript.finalize();

    let strategy = SingleVerifier::new(&params);
    let mut reader = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof[..]);
    let instances: &[&[&[Fp]]] = &[&[&[Fp::from(public_q), Fp::from(public_c)]]];
    verify_proof(&params, pk.get_vk(), strategy, instances, &mut reader).map_err(|_| ())
}

#[test]
fn real_proof_correct_public_inputs_verifies() {
    assert!(prove_and_verify(100, 20).is_ok());
}

#[test]
fn real_proof_wrong_quota_fails() {
    assert!(prove_and_verify(101, 20).is_err());
}

#[test]
fn real_proof_wrong_cost_fails() {
    assert!(prove_and_verify(100, 21).is_err());
}
