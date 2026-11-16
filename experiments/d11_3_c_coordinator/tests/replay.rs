//! C10, C11 and C16: nullifier replay, stale commitment and restart recovery.

use std::{
    ffi::OsString,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use d11_3_b_state_transition::StateWitness;
use d11_3_c_coordinator::{
    coordinator::{Coordinator, CoordinatorError},
    proof_verifier::prove_experimental,
    registration::{sign_registration, RegistrationFields},
    state_store::StateStore,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use halo2_proofs::pasta::Fp;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn db_path(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "d11_3_c_replay_{label}_{}_{n}.db",
        std::process::id()
    ))
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

fn witness() -> StateWitness {
    StateWitness {
        budget_id: Fp::from(101u64),
        period_id: Fp::from(7u64),
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

#[test]
fn c10_reused_nullifier_is_rejected_without_state_change() {
    let path = db_path("c10");
    let (signing, verifying) = issuer();
    let coordinator = Coordinator::new(verifying, path.clone());
    let w = witness();
    coordinator
        .register(&sign_registration(&fields(&w), &signing).unwrap())
        .expect("register");
    let (proof, instance) = prove_experimental(&w);

    // Isolate the nullifier check: mark N as used while C_old is still current.
    {
        let mut store = StateStore::open(&path).expect("open");
        store
            .insert_nullifier_raw(&w.budget_id, &w.period_id, &instance[6], 0)
            .expect("seed used nullifier");
    }

    assert!(matches!(
        coordinator.submit_transition(&proof, &instance),
        Err(CoordinatorError::StateConflict(_))
    ));

    let store = StateStore::open(&path).expect("reopen");
    let row = store
        .get_instance(&w.budget_id, &w.period_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.current_version, 0);
    assert_eq!(row.current_commitment, instance[4]);
    assert_eq!(
        store
            .used_nullifier_count(&w.budget_id, &w.period_id)
            .unwrap(),
        1
    );

    drop(store);
    cleanup(&path);
}

#[test]
fn c11_stale_c_old_is_rejected() {
    let path = db_path("c11");
    let (signing, verifying) = issuer();
    let coordinator = Coordinator::new(verifying, path.clone());
    let w = witness();
    coordinator
        .register(&sign_registration(&fields(&w), &signing).unwrap())
        .expect("register");
    let (proof, instance) = prove_experimental(&w);

    coordinator
        .submit_transition(&proof, &instance)
        .expect("first accepted");
    // Same proof now points at a C_old that is no longer the current state.
    assert!(matches!(
        coordinator.submit_transition(&proof, &instance),
        Err(CoordinatorError::StateConflict(_))
    ));

    let store = StateStore::open(&path).expect("open");
    let row = store
        .get_instance(&w.budget_id, &w.period_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.current_version, 1);
    assert_eq!(row.current_commitment, instance[5]);
    assert_eq!(
        store
            .used_nullifier_count(&w.budget_id, &w.period_id)
            .unwrap(),
        1
    );

    drop(store);
    cleanup(&path);
}

#[test]
fn c16_state_and_nullifier_survive_restart() {
    let path = db_path("c16");
    let (signing, verifying) = issuer();
    let w = witness();
    {
        let coordinator = Coordinator::new(verifying.clone(), path.clone());
        coordinator
            .register(&sign_registration(&fields(&w), &signing).unwrap())
            .expect("register");
        let (proof, instance) = prove_experimental(&w);
        coordinator
            .submit_transition(&proof, &instance)
            .expect("accepted");
    } // Coordinator and all its connections are dropped here.

    let store = StateStore::open(&path).expect("reopen after restart");
    let row = store
        .get_instance(&w.budget_id, &w.period_id)
        .unwrap()
        .unwrap();
    let (_, c_old, c_new, n) = w.commitments();
    assert_eq!(row.current_commitment, c_new);
    assert_ne!(row.current_commitment, c_old);
    assert_eq!(row.current_version, 1);
    assert!(store
        .is_nullifier_used(&w.budget_id, &w.period_id, &n)
        .unwrap());
    drop(store);

    // A fresh Coordinator must observe the advanced state and reject the old proof.
    let coordinator = Coordinator::new(verifying, path.clone());
    let (proof, instance) = prove_experimental(&w);
    assert!(matches!(
        coordinator.submit_transition(&proof, &instance),
        Err(CoordinatorError::StateConflict(_))
    ));

    cleanup(&path);
}
