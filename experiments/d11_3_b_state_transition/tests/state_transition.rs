//! D11.3-B.1 integration tests.
//!
//! All negative cases are enforced by `MockProver` constraint failures (not by
//! host-side early rejection). Real-proof tampering tests are separate.

use d11_3_b_state_transition::{
    native_poseidon, state_transition::StateTransitionCircuit, StateWitness, D_KEY, D_NF, D_STATE,
};
use halo2_proofs::{
    arithmetic::Field,
    dev::MockProver,
    pasta::{EqAffine, Fp},
    plonk::{self, Error, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};

/// Determined empirically below; all MockProver and real-proof tests use it.
const K: u32 = 10;

fn honest_witness() -> StateWitness {
    StateWitness {
        budget_id: Fp::from(101u64),
        period_id: Fp::from(7u64),
        quota: 100,
        cost: 20,
        u_old: 30,
        u_new: 50,
        slack: 50,
        r_old: Fp::from(11u64),
        r_new: Fp::from(13u64),
        nf_secret: Fp::from(17u64),
        policy: Fp::from(1u64),
    }
}

fn assert_accepted(w: &StateWitness) {
    let circuit = StateTransitionCircuit::new(w.clone());
    let prover =
        MockProver::run(K, &circuit, vec![w.public_inputs().to_vec()]).expect("MockProver::run");
    assert_eq!(prover.verify(), Ok(()));
}

fn assert_rejected(w: &StateWitness) {
    let circuit = StateTransitionCircuit::new(w.clone());
    let prover =
        MockProver::run(K, &circuit, vec![w.public_inputs().to_vec()]).expect("MockProver::run");
    assert!(
        prover.verify().is_err(),
        "witness must be rejected by constraints"
    );
}

/// `k = 10` was determined empirically: k=9 fails with
/// `NotEnoughRowsAvailable`, k=10 verifies successfully.
#[test]
fn minimal_k_is_ten() {
    let w = honest_witness();
    let circuit = StateTransitionCircuit::new(w.clone());
    let instance = vec![w.public_inputs().to_vec()];
    assert!(matches!(
        MockProver::run(9, &circuit, instance.clone()),
        Err(Error::NotEnoughRowsAvailable { .. })
    ));
    assert_eq!(
        MockProver::run(10, &circuit, instance)
            .expect("MockProver::run at k=10")
            .verify(),
        Ok(())
    );
}

#[test]
fn t01_normal_transfer() {
    assert_accepted(&honest_witness());
}

#[test]
fn t02_exact_exhaustion() {
    let mut w = honest_witness();
    w.u_old = 80;
    w.u_new = 100;
    w.slack = 0;
    assert_accepted(&w);
}

#[test]
fn t03_wrong_u_new() {
    let mut w = honest_witness();
    w.u_new = 51;
    w.slack = 49; // keep 6b satisfied
                  // Build public inputs from this witness so C_new still opens;
                  // the only failing constraint is then 6a itself.
    let public = w.public_inputs().to_vec();
    let circuit = StateTransitionCircuit::new(w);
    let prover = MockProver::run(K, &circuit, vec![public]).expect("MockProver::run");
    assert!(
        prover.verify().is_err(),
        "6a must reject u_new != u_old + c"
    );
}

#[test]
fn t04_wrong_slack() {
    let mut w = honest_witness();
    w.slack = 49;
    assert_rejected(&w);
}

#[test]
fn t05_zero_quota() {
    let mut w = honest_witness();
    w.quota = 0;
    w.u_old = 0;
    w.u_new = 0;
    w.slack = 0;
    assert_rejected(&w);
}

#[test]
fn t06_zero_cost() {
    let mut w = honest_witness();
    w.cost = 0;
    w.u_new = w.u_old;
    assert_rejected(&w);
}

#[test]
fn t07_quota_u32_overflow() {
    let mut w = honest_witness();
    w.quota = 1u64 << 32;
    assert_rejected(&w);
}

#[test]
fn t08_cost_u32_overflow() {
    let mut w = honest_witness();
    w.cost = 1u64 << 32;
    assert_rejected(&w);
}

#[test]
fn t09_u_old_u32_overflow() {
    let mut w = honest_witness();
    w.u_old = 1u64 << 32;
    assert_rejected(&w);
}

#[test]
fn t10_u_new_u32_overflow() {
    let mut w = honest_witness();
    w.u_new = 1u64 << 32;
    assert_rejected(&w);
}

#[test]
fn t11_slack_u32_overflow() {
    let mut w = honest_witness();
    w.slack = 1u64 << 32;
    assert_rejected(&w);
}

#[test]
fn t12_wrong_old_state_opening() {
    let honest = honest_witness();
    // Public inputs are produced from honest r_old; the prover supplies a
    // different r_old, so the old commitment cannot be opened correctly.
    let public = honest.public_inputs();
    let mut attacker = honest.clone();
    attacker.r_old = Fp::from(999u64);
    let circuit = StateTransitionCircuit::new(attacker);
    let prover = MockProver::run(K, &circuit, vec![public.to_vec()]).expect("MockProver::run");
    assert!(prover.verify().is_err());
    // Keep `honest` used so the public inputs are unambiguously from it.
    let _ = &honest;
}

#[test]
fn t13_wrong_new_state_opening() {
    let honest = honest_witness();
    let public = honest.public_inputs();
    let mut attacker = honest;
    attacker.r_new = Fp::from(999u64);
    let circuit = StateTransitionCircuit::new(attacker);
    let prover = MockProver::run(K, &circuit, vec![public.to_vec()]).expect("MockProver::run");
    assert!(prover.verify().is_err());
}

#[test]
fn t14_changed_nf_secret() {
    let honest = honest_witness();
    let public = honest.public_inputs();
    let mut attacker = honest;
    attacker.nf_secret = Fp::from(18u64);
    let circuit = StateTransitionCircuit::new(attacker);
    let prover = MockProver::run(K, &circuit, vec![public.to_vec()]).expect("MockProver::run");
    assert!(prover.verify().is_err());
}

#[test]
fn t15_different_k_for_new_state() {
    let w = honest_witness();
    let k_override = Fp::from(12345u64);
    // Tamper the public C_new to match the attacker's K, so the C_new opening
    // constraint still passes and only the same-K gate can reject the proof.
    let mut public = w.public_inputs().to_vec();
    public[5] = native_poseidon([
        Fp::from(D_STATE),
        w.budget_id,
        w.period_id,
        Fp::from(w.quota),
        Fp::from(w.u_new),
        w.r_new,
        k_override,
    ]);
    let mut circuit = StateTransitionCircuit::new(w);
    circuit.k_new_override = Some(k_override);
    let prover = MockProver::run(K, &circuit, vec![public]).expect("MockProver::run");
    assert!(
        prover.verify().is_err(),
        "C_new using a K different from the gadget-derived K must be rejected"
    );
}

#[test]
fn t16_wrong_nullifier() {
    let honest = honest_witness();
    let mut public = honest.public_inputs().to_vec();
    public[6] = public[6] + Fp::ONE;
    let circuit = StateTransitionCircuit::new(honest);
    let prover = MockProver::run(K, &circuit, vec![public]).expect("MockProver::run");
    assert!(prover.verify().is_err());
}

#[test]
fn maximum_uint32_boundary_is_accepted() {
    let max = (1u64 << 32) - 1;
    let w = StateWitness {
        quota: max,
        cost: max,
        u_old: 0,
        u_new: max,
        slack: 0,
        ..honest_witness()
    };
    assert_accepted(&w);
}

#[test]
fn deterministic_full_transition_vectors() {
    let w = honest_witness();
    let (k, c_old, c_new, n) = w.commitments();
    assert_eq!(
        format!("{k:?}"),
        "0x27fbd2f26cd448c84da5637db500bb5d31f7c22c69c911698bdb43bddc9053e4"
    );
    assert_eq!(
        format!("{c_old:?}"),
        "0x163734fe8ba9e0777560b7e9a72535dde3ae274629014b728a99c7ccca5b8aa1"
    );
    assert_eq!(
        format!("{c_new:?}"),
        "0x1e8d38896a70fe2f189e03c032a252ac4de20aa794c6946b671c62c214f00712"
    );
    assert_eq!(
        format!("{n:?}"),
        "0x071fb308b59421527da6c9de579b7d08171432e30088135b796409b84519c879"
    );

    // The same values must be reproducible from the individual fixed formulas.
    let expected_k = native_poseidon([
        Fp::from(D_KEY),
        Fp::from(17u64),
        Fp::from(101u64),
        Fp::from(7u64),
    ]);
    assert_eq!(k, expected_k);
    let expected_c_old = native_poseidon([
        Fp::from(D_STATE),
        Fp::from(101u64),
        Fp::from(7u64),
        Fp::from(100u64),
        Fp::from(30u64),
        Fp::from(11u64),
        k,
    ]);
    assert_eq!(c_old, expected_c_old);
    let expected_c_new = native_poseidon([
        Fp::from(D_STATE),
        Fp::from(101u64),
        Fp::from(7u64),
        Fp::from(100u64),
        Fp::from(50u64),
        Fp::from(13u64),
        k,
    ]);
    assert_eq!(c_new, expected_c_new);
    let expected_n = native_poseidon([
        Fp::from(D_NF),
        Fp::from(17u64),
        Fp::from(101u64),
        Fp::from(7u64),
        c_old,
    ]);
    assert_eq!(n, expected_n);
}

/// One real proof is created for an honest transition, then verified against
/// the honest instance (must succeed) and against C_old / C_new / N tampering
/// (each must fail). This keeps the expensive keygen/prove to a single run.
#[test]
fn real_proof_honest_verifies_and_t17_t18_t19_tampering_fails() {
    let w = honest_witness();
    let circuit = StateTransitionCircuit::new(w.clone());
    let honest_instance = w.public_inputs().to_vec();

    let params = Params::new(K);
    let vk = plonk::keygen_vk(&params, &circuit).expect("keygen_vk");
    let pk = plonk::keygen_pk(&params, vk, &circuit).expect("keygen_pk");

    let instances: Vec<&[Fp]> = vec![honest_instance.as_slice()];
    let instance_refs: Vec<&[&[Fp]]> = vec![&instances];
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
        "honest full state-transition proof must verify"
    );

    for (row, name) in [(4, "C_old"), (5, "C_new"), (6, "N")] {
        let mut tampered = honest_instance.clone();
        tampered[row] = tampered[row] + Fp::ONE;
        let bad_instances: Vec<&[Fp]> = vec![tampered.as_slice()];
        let bad_refs: Vec<&[&[Fp]]> = vec![&bad_instances];
        let strategy = SingleVerifier::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        assert!(
            plonk::verify_proof(&params, pk.get_vk(), strategy, &bad_refs, &mut transcript)
                .is_err(),
            "{name} tampering must fail real verification"
        );
    }
}
