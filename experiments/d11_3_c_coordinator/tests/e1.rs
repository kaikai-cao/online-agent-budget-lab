//! E1.3 integration tests: cross-layer registration, Python-signed Attestation
//! verification, real Halo2 proof, E1TransitionReceipt, idempotency, crash
//! recovery and concurrent CAS. Group letters R/S/A/B/P/T/I/C/L map to the
//! E1.3 task package §9 acceptance list.

use std::{
    collections::HashMap,
    ffi::OsString,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use d11_3_b_state_transition::StateWitness;
use d11_3_c_coordinator::{
    e1::{
        handle_request, parse_service_request, verify_metering_attestation,
        CrossLayerScopeBindingRecord, E1Coordinator, E1CoordinatorConfig, E1Error,
        E1TransitionReceipt, ServiceRequest, ATTESTATION_DOMAIN,
    },
    e1_encoding::{canonical_json_bytes, fp_to_hex},
    proof_verifier::prove_experimental,
    registration::{sign_registration, RegistrationFields},
    state_store::{CrashPoint, StateStore},
};
use ed25519_dalek::{Signer, SigningKey};
use halo2_proofs::pasta::Fp;
use serde_json::{json, Value};
use sha2::Digest;

static COUNTER: AtomicU64 = AtomicU64::new(0);
// The service validates the attestation against real UTC time. Use a window
// around the actual system clock so submit_transition_e1 tests are not flaky.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
const NOW: u64 = 1_800_000_000; // only used by the Python-vector direct verify test

fn db_path(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("d11_3_e1_{label}_{}_{n}.db", std::process::id()))
}
fn cleanup(path: &PathBuf) {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = OsString::from(path.as_os_str());
        name.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(name));
    }
}

// --------------------------------------------------------------------- fixtures //

struct Fixture {
    path: PathBuf,
    coordinator: E1Coordinator,
    issuer: SigningKey,
    issuer_id: String,
    executor: SigningKey,
    executor_id: String,
    witness: StateWitness,
    auth_bytes: Vec<u8>,
    binding_record: CrossLayerScopeBindingRecord,
    executor_keys: HashMap<String, ed25519_dalek::VerifyingKey>,
    coordinator_pub: HashMap<String, ed25519_dalek::VerifyingKey>,
    coordinator_key_id: String,
    coordinator_signing: SigningKey,
}

impl Fixture {
    fn config_issuer_id(&self) -> String {
        self.issuer_id.clone()
    }
}

fn witness(budget_id: u64, period_id: u64, policy: u64, cost: u64) -> StateWitness {
    StateWitness {
        budget_id: Fp::from(budget_id),
        period_id: Fp::from(period_id),
        quota: 100,
        cost,
        u_old: 0,
        u_new: cost,
        slack: 100 - cost,
        r_old: Fp::from(11u64),
        r_new: Fp::from(13u64),
        nf_secret: Fp::from(17u64),
        policy: Fp::from(policy),
    }
}

fn sha(v: &str) -> String {
    format!("sha256:{}", hex_lower(&sha2::Sha256::digest(v.as_bytes())))
}
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// A binding record consistent with the witness's registered fields.
fn binding_record_for(
    w: &StateWitness,
    issuer_id: &str,
    auth_bytes: &[u8],
) -> CrossLayerScopeBindingRecord {
    CrossLayerScopeBindingRecord {
        version: 1,
        issuer_id: issuer_id.to_owned(),
        global_budget_id: "global-e13-test".to_owned(),
        lease_id: "lease-e13-test".to_owned(),
        online_lease_grant_digest: sha("online-lease-grant"),
        budget_id: fp_to_hex(&w.budget_id),
        period_id: fp_to_hex(&w.period_id),
        q: w.quota,
        p: fp_to_hex(&w.policy),
        metering_policy_digest: sha("metering-policy"),
        registration_authorization_digest: format!(
            "sha256:{}",
            hex_lower(&sha2::Sha256::digest(auth_bytes))
        ),
        signature_b64: String::new(),
    }
}

fn sign_binding_record(
    mut record: CrossLayerScopeBindingRecord,
    issuer: &SigningKey,
) -> CrossLayerScopeBindingRecord {
    let payload = json!({
        "version": record.version,
        "issuer_id": record.issuer_id,
        "global_budget_id": record.global_budget_id,
        "lease_id": record.lease_id,
        "online_lease_grant_digest": record.online_lease_grant_digest,
        "budget_id": record.budget_id,
        "period_id": record.period_id,
        "Q": record.q,
        "P": record.p,
        "metering_policy_digest": record.metering_policy_digest,
        "registration_authorization_digest": record.registration_authorization_digest,
    });
    let msg =
        canonical_json_bytes(&json!({"domain": "d11-e1-cross-layer-scope-v1", "payload": payload}))
            .unwrap();
    record.signature_b64 = b64(&issuer.sign(&msg).to_bytes());
    record
}

/// Sign an Attestation payload in the exact E1.2 canonical format (test fixture;
/// the cross-language interoperability claim is covered separately by the
/// Python-generated vector test `a01_python_vector_*`).
fn sign_attestation(mut payload: Value, executor: &SigningKey) -> Value {
    if let Some(obj) = payload.as_object_mut() {
        // ensure the fixed field set is present
        assert_eq!(obj.len(), 19);
    }
    let msg =
        canonical_json_bytes(&json!({"domain": ATTESTATION_DOMAIN, "payload": &payload})).unwrap();
    let sig = b64(&executor.sign(&msg).to_bytes());
    json!({"attestation": payload, "signature_b64": sig})
}

fn attestation_payload_at(f: &Fixture, issued_at: u64, expires_at: u64) -> Value {
    json!({
        "version": 1,
        "executor_id": f.executor_id,
        "operation_id": "op-e13-1",
        "binding_digest": sha("binding"),
        "executor_authorization_digest": sha("auth-v2"),
        "arguments_digest": sha("arguments"),
        "canonicalization_version": "python-canonical-json-v1",
        "tool_name": "invoice_review",
        "tool_schema_hash": sha("schema"),
        "global_budget_id": "global-e13-test",
        "lease_id": "lease-e13-test",
        "budget_id": fp_to_hex(&f.witness.budget_id),
        "period_id": fp_to_hex(&f.witness.period_id),
        "Q": f.witness.quota,
        "P": fp_to_hex(&f.witness.policy),
        "c": f.witness.cost,
        "metering_policy_digest": f.binding_record.metering_policy_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
    })
}

/// Fixed-time payload for direct `verify_metering_attestation` tests.
fn attestation_payload(f: &Fixture) -> Value {
    attestation_payload_at(f, NOW - 10, NOW + 100)
}

/// Real-time payload for `submit_transition_e1` (service validates against UTC).
fn attestation_payload_live(f: &Fixture) -> Value {
    let n = now();
    attestation_payload_at(f, n - 10, n + 600)
}

fn setup(label: &str) -> Fixture {
    let path = db_path(label);
    let issuer = SigningKey::from_bytes(&[7u8; 32]);
    let executor = SigningKey::from_bytes(&[9u8; 32]);
    let coordinator_signing = SigningKey::from_bytes(&[3u8; 32]);
    let w = witness(101, 7, 1, 20);
    let auth = sign_registration(
        &RegistrationFields {
            budget_id: w.budget_id,
            period_id: w.period_id,
            quota: Fp::from(w.quota),
            policy: w.policy,
            initial_commitment: w.commitments().1,
        },
        &issuer,
    )
    .unwrap();
    let auth_bytes = auth.encode();

    let issuer_id = "issuer-e13-test".to_owned();
    let executor_id = "executor-e13-test".to_owned();
    let coordinator_key_id = "d11-coordinator-v1".to_owned();
    let mut executor_keys = HashMap::new();
    executor_keys.insert(executor_id.clone(), executor.verifying_key());
    let mut coordinator_pub = HashMap::new();
    coordinator_pub.insert(
        coordinator_key_id.clone(),
        coordinator_signing.verifying_key(),
    );

    let config = E1CoordinatorConfig {
        issuer_id: issuer_id.clone(),
        issuer_public_key: issuer.verifying_key(),
        executor_public_keys: executor_keys.clone(),
        coordinator_key_id: coordinator_key_id.clone(),
        coordinator_signing_key: coordinator_signing.clone(),
        coordinator_public_keys: coordinator_pub.clone(),
    };
    let coordinator = E1Coordinator::new(config, path.clone()).unwrap();

    let binding_record =
        sign_binding_record(binding_record_for(&w, &issuer_id, &auth_bytes), &issuer);
    coordinator
        .register_e1(&binding_record, &auth_bytes)
        .unwrap();

    Fixture {
        path,
        coordinator,
        issuer,
        issuer_id,
        executor,
        executor_id,
        witness: w,
        auth_bytes,
        binding_record,
        executor_keys,
        coordinator_pub,
        coordinator_key_id,
        coordinator_signing,
    }
}

/// Full submit payload for the fixture's honest transition.
fn submit_payload(f: &Fixture) -> (Value, String, String, String) {
    let (proof, instance) = prove_experimental(&f.witness);
    let proof_b64 = b64(&proof);
    let instance_hex: Vec<String> = instance.iter().map(fp_to_hex).collect();
    let att = sign_attestation(attestation_payload_live(f), &f.executor);
    let quote =
        d11_3_c_coordinator::e1_encoding::canonical_digest(ATTESTATION_DOMAIN, &att["attestation"])
            .unwrap();
    let binding_digest = att["attestation"]["binding_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    let operation_id = att["attestation"]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let payload = json!({
        "proof_b64": proof_b64,
        "instance": instance_hex,
        "metering_attestation": att,
        "metering_quote_digest": quote,
        "operation_id": operation_id,
        "binding_digest": binding_digest,
    });
    (payload, binding_digest, quote, operation_id)
}

fn submit_via_service(f: &Fixture, payload: Value) -> Result<Value, E1Error> {
    let req = ServiceRequest {
        request_id: "req-e13".to_owned(),
        method: "submit_transition_e1".to_owned(),
        payload,
    };
    handle_request(&f.coordinator, &req)
}

// ------------------------------------------------------------------ R: registration //

#[test]
fn r01_register_e1_happy_path() {
    let f = setup("r01");
    let store = StateStore::open(&f.path).unwrap();
    assert!(store
        .get_instance(&f.witness.budget_id, &f.witness.period_id)
        .unwrap()
        .is_some());
    assert!(store
        .get_cross_layer_scope(&f.witness.budget_id, &f.witness.period_id)
        .unwrap()
        .is_some());
    cleanup(&f.path);
}

#[test]
fn r02_duplicate_registration_rejected() {
    let f = setup("r02");
    let result = f.coordinator.register_e1(&f.binding_record, &f.auth_bytes);
    assert!(
        matches!(result, Err(E1Error::DuplicateRegistration)),
        "got {result:?}"
    );
    cleanup(&f.path);
}

#[test]
fn r03_wrong_issuer_signature_rejected() {
    let f = setup("r03");
    let other_issuer = SigningKey::from_bytes(&[77u8; 32]);
    let bad = sign_binding_record(
        binding_record_for(&f.witness, "issuer-e13-test", &f.auth_bytes),
        &other_issuer,
    );
    let result = f.coordinator.register_e1(&bad, &f.auth_bytes);
    assert!(
        matches!(result, Err(E1Error::InvalidRegistration(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

#[test]
fn r04_tampered_registration_digest_rejected() {
    let path = db_path("r04");
    let issuer = SigningKey::from_bytes(&[7u8; 32]);
    let coordinator_signing = SigningKey::from_bytes(&[3u8; 32]);
    let w = witness(201, 8, 2, 10);
    let auth = sign_registration(
        &RegistrationFields {
            budget_id: w.budget_id,
            period_id: w.period_id,
            quota: Fp::from(w.quota),
            policy: w.policy,
            initial_commitment: w.commitments().1,
        },
        &issuer,
    )
    .unwrap();
    let mut record = binding_record_for(&w, "issuer-e13-test", &auth.encode());
    record.registration_authorization_digest = sha("wrong-digest"); // valid sha256, wrong value
    let record = sign_binding_record(record, &issuer);
    let config = E1CoordinatorConfig {
        issuer_id: "issuer-e13-test".to_owned(),
        issuer_public_key: issuer.verifying_key(),
        executor_public_keys: HashMap::new(),
        coordinator_key_id: "d11-coordinator-v1".to_owned(),
        coordinator_signing_key: coordinator_signing.clone(),
        coordinator_public_keys: HashMap::from([(
            "d11-coordinator-v1".to_owned(),
            coordinator_signing.verifying_key(),
        )]),
    };
    let c = E1Coordinator::new(config, path.clone()).unwrap();
    let result = c.register_e1(&record, &auth.encode());
    assert!(
        matches!(result, Err(E1Error::InvalidRegistration(_))),
        "got {result:?}"
    );
    cleanup(&path);
}

#[test]
fn r05_q_p_mismatch_with_authorization_rejected() {
    let path = db_path("r05");
    let issuer = SigningKey::from_bytes(&[7u8; 32]);
    let cs = SigningKey::from_bytes(&[3u8; 32]);
    let w = witness(202, 9, 2, 10);
    let auth = sign_registration(
        &RegistrationFields {
            budget_id: w.budget_id,
            period_id: w.period_id,
            quota: Fp::from(w.quota),
            policy: w.policy,
            initial_commitment: w.commitments().1,
        },
        &issuer,
    )
    .unwrap();
    let mut record = binding_record_for(&w, "issuer-e13-test", &auth.encode());
    record.p = fp_to_hex(&Fp::from(999u64)); // mismatch vs authorization policy
    let record = sign_binding_record(record, &issuer);
    let config = E1CoordinatorConfig {
        issuer_id: "issuer-e13-test".to_owned(),
        issuer_public_key: issuer.verifying_key(),
        executor_public_keys: HashMap::new(),
        coordinator_key_id: "k".to_owned(),
        coordinator_signing_key: cs.clone(),
        coordinator_public_keys: HashMap::from([("k".to_owned(), cs.verifying_key())]),
    };
    let c = E1Coordinator::new(config, path.clone()).unwrap();
    let result = c.register_e1(&record, &auth.encode());
    assert!(
        matches!(result, Err(E1Error::InvalidRegistration(_))),
        "got {result:?}"
    );
    cleanup(&path);
}

// ------------------------------------------------------------------ S: uniqueness //

#[test]
fn s01_same_scope_different_budget_is_conflict_with_no_partial_write() {
    let f = setup("s01");
    // Register a second budget instance with the same (global,lease,period) but a different budget_id.
    let other_issuer = SigningKey::from_bytes(&[7u8; 32]);
    let w2 = witness(303, 7, 1, 20); // same period_id=7, different budget_id=303
    let auth2 = sign_registration(
        &RegistrationFields {
            budget_id: w2.budget_id,
            period_id: w2.period_id,
            quota: Fp::from(w2.quota),
            policy: w2.policy,
            initial_commitment: w2.commitments().1,
        },
        &other_issuer,
    )
    .unwrap();
    let mut rec2 = binding_record_for(&w2, "issuer-e13-test", &auth2.encode());
    rec2.budget_id = fp_to_hex(&f.witness.budget_id); // force SAME scope key budget_id column clash
                                                      // Actually to trigger scope-key conflict we keep global/lease/period identical (they are by helper)
                                                      // and set a different budget_id. Restore the true w2 budget_id:
    rec2.budget_id = fp_to_hex(&w2.budget_id);
    let rec2 = sign_binding_record(rec2, &other_issuer);
    let result = f.coordinator.register_e1(&rec2, &auth2.encode());
    assert!(
        matches!(result, Err(E1Error::ScopeConflict(_))),
        "got {result:?}"
    );
    // No partial write: w2 budget instance must not be present.
    let store = StateStore::open(&f.path).unwrap();
    assert!(store
        .get_instance(&w2.budget_id, &w2.period_id)
        .unwrap()
        .is_none());
    cleanup(&f.path);
}

// ------------------------------------------------- A: attestation cross-language //

#[test]
fn a01_python_vector_verifies_cross_language() {
    // This vector was produced by the REAL Python E1.2 issue_metering_attestation().
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-vectors/e1_attestation_python_v1.json"
    ))
    .unwrap();
    let v: Value = serde_json::from_str(&text).unwrap();
    let executor_b64 = v["executor_public_key_b64"].as_str().unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(executor_b64)
        .unwrap();
    let arr: [u8; 32] = bytes.try_into().unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).unwrap();
    let keys = HashMap::from([(
        v["attestation"]["executor_id"].as_str().unwrap().to_owned(),
        vk,
    )]);
    let now = v["now"].as_u64().unwrap();
    // The vector stores attestation + signature at top level; rebuild the envelope.
    let envelope = json!({
        "attestation": v["attestation"],
        "signature_b64": v["signature_b64"],
    });
    let verified = verify_metering_attestation(&envelope, &keys, now)
        .expect("Python signature must verify in Rust");
    assert_eq!(
        verified.metering_quote_digest,
        v["metering_quote_digest"].as_str().unwrap()
    );
    assert_eq!(verified.c, v["expected"]["c"].as_u64().unwrap());
    assert_eq!(verified.q, v["expected"]["Q"].as_u64().unwrap());
    assert_eq!(
        verified.budget_id,
        d11_3_c_coordinator::e1_encoding::fp_from_hex_strict(
            v["expected"]["budget_id"].as_str().unwrap()
        )
        .unwrap()
    );
}

#[test]
fn a02_wrong_executor_key_rejected() {
    let f = setup("a02");
    let (_proof, instance) = prove_experimental(&f.witness);
    let att = sign_attestation(attestation_payload(&f), &f.executor);
    let _ = instance;
    let wrong_keys = HashMap::from([(
        f.executor_id.clone(),
        SigningKey::from_bytes(&[55u8; 32]).verifying_key(),
    )]);
    let result = verify_metering_attestation(&att, &wrong_keys, NOW);
    assert!(
        matches!(result, Err(E1Error::AttestationInvalid(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

#[test]
fn a03_unknown_executor_id_rejected() {
    let f = setup("a03");
    let att = sign_attestation(attestation_payload(&f), &f.executor);
    let result = verify_metering_attestation(&att, &HashMap::new(), NOW);
    assert!(
        matches!(result, Err(E1Error::AttestationInvalid(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

#[test]
fn a04_expired_attestation_rejected() {
    let f = setup("a04");
    let att = sign_attestation(attestation_payload(&f), &f.executor);
    let result = verify_metering_attestation(&att, &f.executor_keys, NOW + 1000);
    assert!(
        matches!(result, Err(E1Error::AttestationInvalid(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

#[test]
fn a05_tampered_field_rejected() {
    let f = setup("a05");
    let mut att = sign_attestation(attestation_payload(&f), &f.executor);
    att["attestation"]["c"] = json!(99); // tamper after signing
    let result = verify_metering_attestation(&att, &f.executor_keys, NOW);
    assert!(
        matches!(result, Err(E1Error::AttestationInvalid(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

// ---------------------------------------------------- B: public input boundaries //

#[test]
fn b01_noncanonical_instance_hex_rejected() {
    let f = setup("b01");
    let (mut payload, _, _, _) = submit_payload(&f);
    let arr = payload["instance"].as_array_mut().unwrap();
    arr[0] = json!("ZZ00000000000000000000000000000000000000000000000000000000000000"); // uppercase/nonhex
    let result = submit_via_service(&f, payload);
    assert!(
        matches!(result, Err(E1Error::InvalidPublicInput(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

#[test]
fn b02_cost_mismatch_vs_attestation_rejected() {
    let f = setup("b02");
    let (mut payload, _, _, _) = submit_payload(&f);
    // Change instance[3] (c as Fp hex) to a different valid cost -> c mismatch.
    let other_c = fp_to_hex(&Fp::from(21u64));
    payload["instance"][3] = json!(other_c);
    let result = submit_via_service(&f, payload);
    assert!(
        matches!(result, Err(E1Error::AttestationBindingMismatch(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

#[test]
fn b03_bool_as_q_in_attestation_rejected() {
    let f = setup("b03");
    let att = sign_attestation_value_with(&f, |mut p| {
        p["Q"] = json!(true);
        p
    });
    let result = verify_metering_attestation(&att, &f.executor_keys, NOW);
    assert!(
        matches!(result, Err(E1Error::AttestationInvalid(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

fn sign_attestation_value_with(f: &Fixture, edit: impl FnOnce(Value) -> Value) -> Value {
    let p = edit(attestation_payload(f));
    sign_attestation(p, &f.executor)
}

// ------------------------------------------------------ P: real Halo2 proof //

#[test]
fn p01_honest_real_proof_accepted() {
    let f = setup("p01");
    let (payload, binding, quote, _op) = submit_payload(&f);
    let result = submit_via_service(&f, payload).expect("honest submit accepted");
    let receipt = E1TransitionReceipt::from_value(&result).unwrap();
    assert_eq!(receipt.state_version, 1);
    assert_eq!(receipt.binding_digest, binding);
    assert_eq!(receipt.metering_quote_digest, quote);
    cleanup(&f.path);
}

#[test]
fn p02_malformed_proof_rejected() {
    let f = setup("p02");
    let (mut payload, _, _, _) = submit_payload(&f);
    payload["proof_b64"] = json!("!!!!not-base64!!!!");
    let result = submit_via_service(&f, payload);
    assert!(
        matches!(result, Err(E1Error::InvalidPublicInput(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

#[test]
fn p03_modified_instance_rejects_proof() {
    let f = setup("p03");
    let (mut payload, _, _, _) = submit_payload(&f);
    // Tamper C_old (instance[4]) so the proof no longer verifies; keep attestation intact.
    let fake = fp_to_hex(&Fp::from(999999u64));
    payload["instance"][4] = json!(fake);
    let result = submit_via_service(&f, payload);
    assert!(
        matches!(result, Err(E1Error::ProofVerification(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

// ------------------------------------------- T: transition receipt digest/signature //

#[test]
fn t01_digest_and_signature_validate() {
    let f = setup("t01");
    let (payload, _, _, _) = submit_payload(&f);
    let result = submit_via_service(&f, payload).unwrap();
    let receipt = E1TransitionReceipt::from_value(&result).unwrap();
    assert!(receipt.compute_digest().unwrap() == receipt.transition_digest);
    let op_row = StateStore::open(&f.path)
        .unwrap()
        .get_operation_row(&receipt.operation_id)
        .unwrap()
        .unwrap();
    receipt
        .verify(
            &f.coordinator_pub,
            &op_row,
            &receipt.binding_digest,
            &receipt.metering_quote_digest,
        )
        .unwrap();
    cleanup(&f.path);
}

#[test]
fn t02_tampered_receipt_digest_rejected() {
    let f = setup("t02");
    let (payload, _, _, _) = submit_payload(&f);
    let result = submit_via_service(&f, payload).unwrap();
    let mut receipt = E1TransitionReceipt::from_value(&result).unwrap();
    receipt.new_commitment = fp_to_hex(&Fp::from(1u64)); // tamper after sign
    assert_ne!(receipt.compute_digest().unwrap(), receipt.transition_digest);
    cleanup(&f.path);
}

#[test]
fn t03_unknown_coordinator_key_rejected() {
    let f = setup("t03");
    let (payload, _, _, _) = submit_payload(&f);
    let result = submit_via_service(&f, payload).unwrap();
    let receipt = E1TransitionReceipt::from_value(&result).unwrap();
    let op_row = StateStore::open(&f.path)
        .unwrap()
        .get_operation_row(&receipt.operation_id)
        .unwrap()
        .unwrap();
    let empty = HashMap::new();
    assert!(matches!(
        receipt.verify(
            &empty,
            &op_row,
            &receipt.binding_digest,
            &receipt.metering_quote_digest
        ),
        Err(E1Error::IdempotencyConflict(_))
    ));
    cleanup(&f.path);
}

// ------------------------------------------------------ I: idempotency //

#[test]
fn i01_same_request_returns_stored_receipt_no_double_spend() {
    let f = setup("i01");
    let (payload, binding, quote, op) = submit_payload(&f);
    let r1 = submit_via_service(&f, payload.clone()).unwrap();
    let r2 = submit_via_service(&f, payload).unwrap();
    assert_eq!(r1, r2, "idempotent receipt must be byte-identical");
    let version = StateStore::open(&f.path)
        .unwrap()
        .get_instance(&f.witness.budget_id, &f.witness.period_id)
        .unwrap()
        .unwrap()
        .current_version;
    assert_eq!(version, 1, "state advanced exactly once");
    let recovered = f
        .coordinator
        .get_operation(&op, &binding, &quote)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.to_value(), r1);
    cleanup(&f.path);
}

#[test]
fn i02_same_id_different_binding_is_conflict() {
    let f = setup("i02");
    let (payload, _, _, op) = submit_payload(&f);
    submit_via_service(&f, payload.clone()).unwrap();
    let mut payload2 = payload;
    payload2["binding_digest"] = json!(sha("different-binding"));
    // Recompute attestation to carry the new binding and a matching quote so it
    // reaches the idempotency check rather than failing at signature verification.
    let mut att = payload2["metering_attestation"].clone();
    att["attestation"]["binding_digest"] = payload2["binding_digest"].clone();
    att = sign_attestation_raw(att, &f.executor);
    payload2["metering_attestation"] = att.clone();
    payload2["metering_quote_digest"] = json!(d11_3_c_coordinator::e1_encoding::canonical_digest(
        ATTESTATION_DOMAIN,
        &att["attestation"]
    )
    .unwrap());
    let _ = op;
    let result = submit_via_service(&f, payload2);
    assert!(
        matches!(result, Err(E1Error::IdempotencyConflict(_))),
        "got {result:?}"
    );
    cleanup(&f.path);
}

fn sign_attestation_raw(mut envelope: Value, executor: &SigningKey) -> Value {
    let payload = envelope["attestation"].clone();
    let msg =
        canonical_json_bytes(&json!({"domain": ATTESTATION_DOMAIN, "payload": &payload})).unwrap();
    envelope["signature_b64"] = json!(b64(&executor.sign(&msg).to_bytes()));
    envelope
}

// ------------------------------------------------------- C: crash recovery //

fn coordinator_with_crash(f: &Fixture, crash: Option<CrashPoint>) -> E1Coordinator {
    let config = E1CoordinatorConfig {
        issuer_id: f.config_issuer_id(),
        issuer_public_key: f.issuer.verifying_key(),
        executor_public_keys: f.executor_keys.clone(),
        coordinator_key_id: f.coordinator_key_id.clone(),
        coordinator_signing_key: f.coordinator_signing.clone(),
        coordinator_public_keys: f.coordinator_pub.clone(),
    };
    let mut c = E1Coordinator::new(config, f.path.clone()).unwrap();
    c.set_crash_point(crash);
    c
}

#[test]
fn c01_crash_before_commit_rolls_back_everything() {
    let f = setup("c01");
    let (payload, _, _, _) = submit_payload(&f);
    let c = coordinator_with_crash(&f, Some(CrashPoint::BeforeCommit));
    let req = ServiceRequest {
        request_id: "r".to_owned(),
        method: "submit_transition_e1".to_owned(),
        payload,
    };
    // Crash before commit surfaces as an error to this call.
    assert!(handle_request(&c, &req).is_err());
    // State unchanged, no nullifier, no operation row.
    let store = StateStore::open(&f.path).unwrap();
    let row = store
        .get_instance(&f.witness.budget_id, &f.witness.period_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        row.current_version, 0,
        "state must not advance on pre-commit crash"
    );
    assert_eq!(row.current_commitment, f.witness.commitments().1);
    let (_proof, instance) = prove_experimental(&f.witness);
    assert!(!store
        .is_nullifier_used(&f.witness.budget_id, &f.witness.period_id, &instance[6])
        .unwrap());
    assert!(store.get_operation_row("op-e13-1").unwrap().is_none());
    cleanup(&f.path);
}

#[test]
fn c02_crash_after_commit_recovers_identical_receipt() {
    let f = setup("c02");
    let (payload, binding, quote, op) = submit_payload(&f);
    let c = coordinator_with_crash(&f, Some(CrashPoint::AfterCommit));
    let req = ServiceRequest {
        request_id: "r".to_owned(),
        method: "submit_transition_e1".to_owned(),
        payload,
    };
    // Crash after commit: rows are durable even though this call reports error.
    assert!(handle_request(&c, &req).is_err());
    // Simulate a genuine process restart with a FRESH coordinator.
    let fresh = coordinator_with_crash(&f, None);
    let recovered = fresh
        .get_operation(&op, &binding, &quote)
        .unwrap()
        .expect("receipt recoverable");
    assert_eq!(recovered.state_version, 1);
    // Verify signature under trusted key and cross-check DB row byte-for-byte.
    let op_row = StateStore::open(&f.path)
        .unwrap()
        .get_operation_row(&op)
        .unwrap()
        .unwrap();
    recovered
        .verify(&f.coordinator_pub, &op_row, &binding, &quote)
        .unwrap();
    assert_eq!(
        recovered.to_bytes().unwrap(),
        op_row.receipt_blob,
        "receipt blob returned verbatim"
    );
    // No double-spend on recovery: state advanced exactly once.
    let version = StateStore::open(&f.path)
        .unwrap()
        .get_instance(&f.witness.budget_id, &f.witness.period_id)
        .unwrap()
        .unwrap()
        .current_version;
    assert_eq!(version, 1);
    cleanup(&f.path);
}

#[test]
fn c03_trigger_failure_rolls_back_no_half_commit() {
    let f = setup("c03");
    // Install a SQLite trigger that aborts any insert into budget_operations.
    {
        let store = StateStore::open(&f.path).unwrap();
        // raw connection access via a fresh rusqlite connection on same file
        // (StateStore doesn't expose conn, so open one directly).
        let conn = rusqlite::Connection::open(&f.path).unwrap();
        conn.execute_batch(
            "CREATE TRIGGER IF NOT EXISTS fail_budget_ops \
             BEFORE INSERT ON budget_operations BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )
        .unwrap();
        drop(store);
    }
    let (payload, _, _, _) = submit_payload(&f);
    let result = submit_via_service(&f, payload);
    assert!(result.is_err());
    // No state advance and no nullifier (full rollback).
    let store = StateStore::open(&f.path).unwrap();
    let row = store
        .get_instance(&f.witness.budget_id, &f.witness.period_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.current_version, 0);
    let (_proof, instance) = prove_experimental(&f.witness);
    assert!(!store
        .is_nullifier_used(&f.witness.budget_id, &f.witness.period_id, &instance[6])
        .unwrap());
    cleanup(&f.path);
}

// ------------------------------------------------------------- L: concurrency //

#[test]
fn l01_two_operations_racing_same_c_old_exactly_one_succeeds() {
    use std::sync::Arc;
    let f = setup("l01");
    // Two distinct operation_ids/attestations but identical instance (same C_old, same N).
    let (payload1, _, _, _) = submit_payload(&f);
    let mut payload2 = payload1.clone();
    payload2["operation_id"] = json!("op-e13-2");
    let mut att2 = payload2["metering_attestation"].clone();
    att2["attestation"]["operation_id"] = json!("op-e13-2");
    att2 = sign_attestation_raw(att2, &f.executor);
    payload2["metering_attestation"] = att2.clone();
    payload2["metering_quote_digest"] = json!(d11_3_c_coordinator::e1_encoding::canonical_digest(
        ATTESTATION_DOMAIN,
        &att2["attestation"]
    )
    .unwrap());

    let c1 = Arc::new(coordinator_with_crash(&f, None));
    let c2 = Arc::new(coordinator_with_crash(&f, None));
    let a1 = Arc::clone(&c1);
    let a2 = Arc::clone(&c2);
    let h1 = std::thread::spawn(move || {
        let req = ServiceRequest {
            request_id: "a".to_owned(),
            method: "submit_transition_e1".to_owned(),
            payload: payload1,
        };
        handle_request(&a1, &req).is_ok()
    });
    let h2 = std::thread::spawn(move || {
        let req = ServiceRequest {
            request_id: "b".to_owned(),
            method: "submit_transition_e1".to_owned(),
            payload: payload2,
        };
        handle_request(&a2, &req).is_ok()
    });
    let ok1 = h1.join().unwrap();
    let ok2 = h2.join().unwrap();
    assert_eq!(
        ok1 as u8 + ok2 as u8,
        1,
        "exactly one concurrent submit must succeed"
    );
    let version = StateStore::open(&f.path)
        .unwrap()
        .get_instance(&f.witness.budget_id, &f.witness.period_id)
        .unwrap()
        .unwrap()
        .current_version;
    assert_eq!(version, 1);
    cleanup(&f.path);
}

// ------------------------------------------------- service parse smoke (J part) //

#[test]
fn j00_request_envelope_parse() {
    let line = r#"{"request_id":"x","method":"health","payload":{}}"#;
    let req = parse_service_request(line).unwrap();
    assert_eq!(req.method, "health");
    assert!(parse_service_request(r#"{"request_id":"x","method":"health"}"#).is_err());
}

#[test]
fn i03_same_id_different_state_artifacts_rejected() {
    // E1.0 §6.3: same operation_id but a DIFFERENT transition (different
    // new_commitment/nullifier) must be rejected, never reuse the old receipt.
    let f = setup("i03");
    let (payload, _, _, _) = submit_payload(&f);
    submit_via_service(&f, payload.clone()).expect("first submit ok");

    // Build a second, also-valid witness with the same budget/period/Q/c/P but a
    // different r_new -> different C_new, and different nf_secret -> different N.
    let mut w2 = f.witness.clone();
    w2.r_new = Fp::from(77u64);
    w2.nf_secret = Fp::from(88u64);
    let (proof2, instance2) = prove_experimental(&w2);
    let instance_hex: Vec<String> = instance2.iter().map(fp_to_hex).collect();
    // Keep the SAME attestation/quote/operation_id/binding from the first submit.
    let mut payload2 = payload.clone();
    payload2["proof_b64"] = json!(b64(&proof2));
    payload2["instance"] = json!(instance_hex);
    let result = submit_via_service(&f, payload2);
    assert!(
        matches!(result, Err(E1Error::IdempotencyConflict(_))),
        "got {result:?}"
    );
    // State advanced only once; original receipt still intact.
    let version = StateStore::open(&f.path)
        .unwrap()
        .get_instance(&f.witness.budget_id, &f.witness.period_id)
        .unwrap()
        .unwrap()
        .current_version;
    assert_eq!(version, 1);
    cleanup(&f.path);
}
