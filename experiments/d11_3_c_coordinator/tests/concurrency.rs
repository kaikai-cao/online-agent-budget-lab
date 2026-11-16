//! C14–C15: real concurrent contention and transactional rollback.

use std::{
    ffi::OsString,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier,
    },
    thread,
};

use d11_3_b_state_transition::StateWitness;
use d11_3_c_coordinator::{
    coordinator::{Coordinator, CoordinatorError},
    proof_verifier::prove_experimental,
    registration::{sign_registration, RegistrationFields},
    state_store::StateStore,
};
use ed25519_dalek::SigningKey;
use halo2_proofs::pasta::Fp;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn db_path(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "d11_3_c_conc_{label}_{}_{n}.db",
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

fn registered(path: &PathBuf) -> (Coordinator, StateWitness, Vec<u8>, [Fp; 8]) {
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let coordinator = Coordinator::new(signing.verifying_key(), path.clone());
    let w = witness();
    coordinator
        .register(&sign_registration(&fields(&w), &signing).unwrap())
        .expect("register");
    let (proof, instance) = prove_experimental(&w);
    (coordinator, w, proof, instance)
}

#[test]
fn c14_two_concurrent_requests_competing_for_same_c_old() {
    let path = db_path("c14");
    let (coordinator, w, proof, instance) = registered(&path);
    let coordinator = Arc::new(coordinator);
    let barrier = Arc::new(Barrier::new(2));

    // Two OS threads with a start barrier: this is real lock contention, not
    // two sequential calls. Both submit the same valid proof/instance.
    let handles = (0..2)
        .map(|_| {
            let coordinator = Arc::clone(&coordinator);
            let barrier = Arc::clone(&barrier);
            let proof = proof.clone();
            let instance = instance;
            thread::spawn(move || {
                barrier.wait();
                coordinator.submit_transition(&proof, &instance)
            })
        })
        .collect::<Vec<_>>();

    let accepted = handles
        .into_iter()
        .filter_map(|handle| handle.join().expect("worker panicked").ok())
        .count();
    assert_eq!(accepted, 1, "at most one competing request may commit");

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
fn c15_failed_state_update_leaves_no_nullifier() {
    let path = db_path("c15");
    let (coordinator, w, proof, instance) = registered(&path);

    // Inject a DB failure that aborts the state UPDATE after the nullifier
    // INSERT has already run inside the transaction.
    {
        let conn = rusqlite::Connection::open(&path).expect("open raw sqlite");
        conn.execute_batch(
            "CREATE TRIGGER fail_state_update BEFORE UPDATE ON budget_instances
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .expect("create trigger");
    }

    assert!(matches!(
        coordinator.submit_transition(&proof, &instance),
        Err(CoordinatorError::Store(_))
    ));

    let store = StateStore::open(&path).expect("open");
    let row = store
        .get_instance(&w.budget_id, &w.period_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.current_version, 0);
    assert_eq!(row.current_commitment, instance[4]);
    assert!(!store
        .is_nullifier_used(&w.budget_id, &w.period_id, &instance[6])
        .unwrap());
    assert_eq!(
        store
            .used_nullifier_count(&w.budget_id, &w.period_id)
            .unwrap(),
        0
    );

    drop(store);
    cleanup(&path);
}
