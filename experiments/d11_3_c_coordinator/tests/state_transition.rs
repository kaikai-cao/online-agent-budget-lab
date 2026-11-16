//! C05–C09 and C12–C13: real-proof acceptance, malformed inputs and isolation.

use std::{
    ffi::OsString,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use d11_3_b_state_transition::StateWitness;
use d11_3_c_coordinator::{
    coordinator::Coordinator,
    proof_verifier::prove_experimental,
    registration::{sign_registration, RegistrationFields},
    state_store::StateStore,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use halo2_proofs::pasta::Fp;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn db_path(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("d11_3_c_st_{label}_{}_{n}.db", std::process::id()))
}

fn cleanup(path: &PathBuf) {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = OsString::from(path.as_os_str());
        name.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(name));
    }
}

fn issuer() -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

fn witness(budget_id: u64, period_id: u64) -> StateWitness {
    StateWitness {
        budget_id: Fp::from(budget_id),
        period_id: Fp::from(period_id),
        quota: 100,
        cost: 20,
        u_old: 0,
        u_new: 20,
        slack: 80,
        r_old: Fp::from(11u64),
        r_new: Fp::from(13u64),
        nf_secret: Fp::from(17u64),
        policy: Fp::from(1u64),
    }
}

fn fields(w: &StateWitness) -> RegistrationFields {
    RegistrationFields {
        budget_id: w.budget_id,
        period_id: w.period_id,
        quota: Fp::from(w.quota),
        policy: w.policy,
        initial_commitment: w.commitments().1,
    }
}

fn setup(label: &str, w: &StateWitness) -> (PathBuf, Coordinator, SigningKey, Vec<u8>, [Fp; 8]) {
    let path = db_path(label);
    let (signing, verifying) = issuer();
    let coordinator = Coordinator::new(verifying, path.clone());
    let auth = sign_registration(&fields(w), &signing).expect("sign");
    coordinator.register(&auth).expect("register");
    let (proof, instance) = prove_experimental(w);
    (path, coordinator, signing, proof, instance)
}

#[test]
fn c05_unregistered_instance_is_rejected() {
    let path = db_path("c05");
    let (_, verifying) = issuer();
    let coordinator = Coordinator::new(verifying, path.clone());
    let (proof, instance) = prove_experimental(&witness(101, 7));

    assert!(matches!(
        coordinator.submit_transition(&proof, &instance),
        Err(d11_3_c_coordinator::CoordinatorError::UnregisteredInstance)
    ));

    cleanup(&path);
}

#[test]
fn c06_legitimate_real_halo2_transition_is_accepted() {
    let w = witness(101, 7);
    let (path, coordinator, _, proof, instance) = setup("c06", &w);

    let receipt = coordinator
        .submit_transition(&proof, &instance)
        .expect("honest proof accepted");
    assert_eq!(receipt.version, 1);
    assert_eq!(receipt.new_commitment, instance[5]);
    assert_eq!(receipt.nullifier, instance[6]);

    let store = StateStore::open(&path).expect("open");
    let row = store
        .get_instance(&w.budget_id, &w.period_id)
        .unwrap()
        .expect("row");
    assert_eq!(row.current_commitment, instance[5]);
    assert_eq!(row.current_version, 1);
    assert!(store
        .is_nullifier_used(&w.budget_id, &w.period_id, &instance[6])
        .unwrap());

    drop(store);
    cleanup(&path);
}

#[test]
fn c07_invalid_proof_bytes_are_rejected() {
    let w = witness(101, 7);
    let (path, coordinator, _, _, instance) = setup("c07", &w);

    assert!(matches!(
        coordinator.submit_transition(&vec![0u8; 128], &instance),
        Err(d11_3_c_coordinator::CoordinatorError::ProofVerification(_))
    ));

    cleanup(&path);
}

#[test]
fn c08_tampered_public_c_new_is_rejected() {
    let w = witness(101, 7);
    let (path, coordinator, _, proof, mut instance) = setup("c08", &w);
    instance[5] = instance[5] + Fp::from(1u64);

    assert!(matches!(
        coordinator.submit_transition(&proof, &instance),
        Err(d11_3_c_coordinator::CoordinatorError::ProofVerification(_))
    ));

    let store = StateStore::open(&path).expect("open");
    let row = store
        .get_instance(&w.budget_id, &w.period_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.current_version, 0);

    drop(store);
    cleanup(&path);
}

#[test]
fn c09_tampered_public_policy_is_rejected() {
    let w = witness(101, 7);
    let (path, coordinator, _, proof, mut instance) = setup("c09", &w);
    instance[7] = instance[7] + Fp::from(1u64);

    assert!(matches!(
        coordinator.submit_transition(&proof, &instance),
        Err(d11_3_c_coordinator::CoordinatorError::PolicyMismatch)
    ));

    cleanup(&path);
}

#[test]
fn c12_different_budget_instances_are_isolated() {
    let path = db_path("c12");
    let (signing, verifying) = issuer();
    let coordinator = Coordinator::new(verifying, path.clone());
    let first = witness(101, 7);
    let second = witness(102, 7);
    for w in [&first, &second] {
        coordinator
            .register(&sign_registration(&fields(w), &signing).unwrap())
            .expect("register");
    }
    let (proof_a, instance_a) = prove_experimental(&first);
    let (proof_b, instance_b) = prove_experimental(&second);

    coordinator
        .submit_transition(&proof_a, &instance_a)
        .expect("first accepted");
    coordinator
        .submit_transition(&proof_b, &instance_b)
        .expect("second accepted");
    // A proof from instance 101 must not advance instance 102.
    assert!(coordinator
        .submit_transition(&proof_a, &instance_b)
        .is_err());

    let store = StateStore::open(&path).expect("open");
    let row_a = store
        .get_instance(&Fp::from(101u64), &Fp::from(7u64))
        .unwrap()
        .unwrap();
    let row_b = store
        .get_instance(&Fp::from(102u64), &Fp::from(7u64))
        .unwrap()
        .unwrap();
    assert_eq!(row_a.current_commitment, instance_a[5]);
    assert_eq!(row_b.current_commitment, instance_b[5]);
    assert_ne!(row_a.current_commitment, row_b.current_commitment);
    assert_eq!(
        store
            .used_nullifier_count(&Fp::from(101u64), &Fp::from(7u64))
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .used_nullifier_count(&Fp::from(102u64), &Fp::from(7u64))
            .unwrap(),
        1
    );

    drop(store);
    cleanup(&path);
}

#[test]
fn c13_different_periods_are_isolated() {
    let path = db_path("c13");
    let (signing, verifying) = issuer();
    let coordinator = Coordinator::new(verifying, path.clone());
    let first = witness(101, 7);
    let second = witness(101, 8);
    for w in [&first, &second] {
        coordinator
            .register(&sign_registration(&fields(w), &signing).unwrap())
            .expect("register");
    }
    let (proof_a, instance_a) = prove_experimental(&first);
    let (proof_b, instance_b) = prove_experimental(&second);

    coordinator
        .submit_transition(&proof_a, &instance_a)
        .expect("period 7 accepted");
    coordinator
        .submit_transition(&proof_b, &instance_b)
        .expect("period 8 accepted");
    assert!(coordinator
        .submit_transition(&proof_a, &instance_b)
        .is_err());

    let store = StateStore::open(&path).expect("open");
    let row_a = store
        .get_instance(&Fp::from(101u64), &Fp::from(7u64))
        .unwrap()
        .unwrap();
    let row_b = store
        .get_instance(&Fp::from(101u64), &Fp::from(8u64))
        .unwrap()
        .unwrap();
    assert_eq!(row_a.current_commitment, instance_a[5]);
    assert_eq!(row_b.current_commitment, instance_b[5]);
    assert_ne!(row_a.current_commitment, row_b.current_commitment);

    drop(store);
    cleanup(&path);
}
