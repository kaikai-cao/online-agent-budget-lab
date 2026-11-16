//! C01–C04: issuer registration authorization.

use std::{
    ffi::OsString,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use d11_3_b_state_transition::StateWitness;
use d11_3_c_coordinator::{
    coordinator::CoordinatorError,
    registration::{sign_registration, RegistrationAuthorization, RegistrationFields},
    state_store::StateStore,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use halo2_proofs::pasta::Fp;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn db_path(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("d11_3_c_reg_{label}_{}_{n}.db", std::process::id()))
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
fn c01_legitimate_issuer_registration_is_accepted() {
    let path = db_path("c01");
    let (signing, verifying) = issuer();
    let w = witness();
    let auth = sign_registration(&fields(&w), &signing).expect("sign");

    // Encoding is canonical and round-trips exactly.
    assert_eq!(
        RegistrationAuthorization::decode(&auth.encode()).unwrap(),
        auth
    );
    auth.verify(&verifying).expect("valid signature");

    let coordinator = d11_3_c_coordinator::coordinator::Coordinator::new(verifying, path.clone());
    coordinator.register(&auth).expect("registration accepted");

    let store = StateStore::open(&path).expect("open store");
    let row = store
        .get_instance(&w.budget_id, &w.period_id)
        .expect("query")
        .expect("registered row");
    assert_eq!(row.quota, Fp::from(100u64));
    assert_eq!(row.policy, Fp::from(1u64));
    assert_eq!(row.current_commitment, w.commitments().1);
    assert_eq!(row.current_version, 0);
    assert_eq!(row.authorization_bytes, auth.encode());

    drop(store);
    cleanup(&path);
}

#[test]
fn c02_tampered_registration_signature_is_rejected() {
    let path = db_path("c02");
    let (signing, verifying) = issuer();
    let mut auth = sign_registration(&fields(&witness()), &signing).expect("sign");
    auth.issuer_signature[0] ^= 0x01;

    assert!(auth.verify(&verifying).is_err());
    let coordinator = d11_3_c_coordinator::coordinator::Coordinator::new(verifying, path.clone());
    assert!(matches!(
        coordinator.register(&auth),
        Err(CoordinatorError::InvalidAuthorization(_))
    ));
    let store = StateStore::open(&path).expect("open");
    assert!(store
        .get_instance(&Fp::from(101u64), &Fp::from(7u64))
        .unwrap()
        .is_none());

    drop(store);
    cleanup(&path);
}

#[test]
fn c03_registration_fields_do_not_match_signature() {
    let path = db_path("c03");
    let (signing, verifying) = issuer();
    let mut auth = sign_registration(&fields(&witness()), &signing).expect("sign");
    // Change a signed field while keeping the old signature.
    auth.fields.quota = Fp::from(200u64);

    assert!(auth.verify(&verifying).is_err());
    let coordinator = d11_3_c_coordinator::coordinator::Coordinator::new(verifying, path.clone());
    assert!(matches!(
        coordinator.register(&auth),
        Err(CoordinatorError::InvalidAuthorization(_))
    ));

    cleanup(&path);
}

#[test]
fn c04_duplicate_and_conflicting_registration_are_rejected() {
    let path = db_path("c04");
    let (signing, verifying) = issuer();
    let w = witness();
    let auth = sign_registration(&fields(&w), &signing).expect("sign");
    let coordinator = d11_3_c_coordinator::coordinator::Coordinator::new(verifying, path.clone());
    coordinator.register(&auth).expect("first registration");

    // Same key, same authorization: rejected as duplicate.
    assert!(matches!(
        coordinator.register(&auth),
        Err(CoordinatorError::DuplicateRegistration)
    ));

    // Same key, different C_0 and a genuinely valid issuer signature: also
    // rejected, so the initial state cannot be replaced by a second registration.
    let mut conflicting = w.clone();
    conflicting.r_old = Fp::from(999u64);
    let other = sign_registration(&fields(&conflicting), &signing).expect("sign");
    assert!(other.verify(&coordinator_verifying_key(&signing)).is_ok());
    assert!(matches!(
        coordinator.register(&other),
        Err(CoordinatorError::DuplicateRegistration)
    ));

    let store = StateStore::open(&path).expect("open");
    let row = store
        .get_instance(&w.budget_id, &w.period_id)
        .unwrap()
        .expect("row");
    assert_eq!(row.current_commitment, w.commitments().1);

    drop(store);
    cleanup(&path);
}

fn coordinator_verifying_key(signing: &SigningKey) -> VerifyingKey {
    signing.verifying_key()
}
