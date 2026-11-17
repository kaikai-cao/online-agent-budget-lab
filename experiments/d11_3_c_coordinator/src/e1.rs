//! D11.3-E1.3 — cross-layer Coordinator extension and atomic persistence.
//!
//! This module is strictly additive: it never changes the frozen C-stage
//! five-field `TransitionReceipt`, `submit_transition`, registration encoding or
//! proof verification. It adds:
//!   * Issuer-signed cross-layer scope registration with SQLite UNIQUE(scope);
//!   * verification of the E1.2 Python-signed Metering Attestation (real
//!     Ed25519 + canonical bytes + strict field/uint32/Fp checks);
//!   * `E1TransitionReceipt` with domain-separated digest + Coordinator
//!     signature, built and signed *inside* the commit transaction;
//!   * idempotent `get_operation` that reads the stored receipt_blob verbatim,
//!     re-verifies digest and signature, and never trusts SQLite as the source
//!     of authenticity.
//!
//! Honest scope: this module does NOT re-verify the D10 ExecutorAuthorization
//! signature/parameter binding against a live ToolCallBinding (that is E1.4).
//! It checks the attestation's own Executor signature, field set, format,
//! registered scope and c/instance binding, and the two digest fields it can
//! independently validate here.

use std::{
    collections::HashMap,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ff::Field;
use halo2_proofs::pasta::Fp;
use serde_json::{json, Map, Value};
use sha2::Digest;

use crate::{
    e1_encoding::{
        canonical_digest, canonical_json_bytes, fp_from_hex_strict, fp_hex_to_u32, is_sha256,
        proof_b64_decode,
    },
    fp_to_hex,
    proof_verifier::{ProofVerifier, ProofVerifyError},
    registration::RegistrationAuthorization,
    state_store::{
        CrashPoint, E1BuiltReceipt, E1CommitOutcome, E1OperationParams, E1OperationRow, StateStore,
        StoreError,
    },
    INSTANCE_ROWS, MAX_UINT32,
};

// --------------------------------------------------------------------------- // doma... //
/// Frozen domain separators (E1.0 §3 / §5 / §6.2.3 and E1.3 task §3.1).
pub const CROSS_LAYER_SCOPE_DOMAIN: &str = "d11-e1-cross-layer-scope-v1";
pub const ATTESTATION_DOMAIN: &str = "d11-e1-metering-attestation-v1";
pub const RECEIPT_DOMAIN: &str = "d11-e1-transition-receipt-v1";
pub const RECEIPT_SIGN_DOMAIN: &str = "d11-e1-transition-receipt-sign-v1";

const ATTESTATION_FIELDS: [&str; 19] = [
    "version",
    "executor_id",
    "operation_id",
    "binding_digest",
    "executor_authorization_digest",
    "arguments_digest",
    "canonicalization_version",
    "tool_name",
    "tool_schema_hash",
    "global_budget_id",
    "lease_id",
    "budget_id",
    "period_id",
    "Q",
    "P",
    "c",
    "metering_policy_digest",
    "issued_at",
    "expires_at",
];

const RECEIPT_FULL_FIELDS: [&str; 11] = [
    "operation_id",
    "binding_digest",
    "metering_quote_digest",
    "budget_id",
    "period_id",
    "state_version",
    "new_commitment",
    "nullifier",
    "coordinator_key_id",
    "transition_digest",
    "coordinator_signature",
];

// --------------------------------------------------------------------------- // errors //

/// Stable E1 errors; the JSON Lines service maps these to the §B.5 codes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum E1Error {
    InvalidPublicInput(String),
    UnregisteredInstance,
    InvalidRegistration(String),
    QuotaMismatch,
    PolicyMismatch,
    ProofVerification(String),
    StateConflict(String),
    Store(String),
    DuplicateRegistration,
    ScopeConflict(String),
    AttestationInvalid(String),
    AttestationBindingMismatch(String),
    IdempotencyConflict(String),
    ServiceConfig(String),
}

impl E1Error {
    /// Stable error code used by the JSON Lines protocol (E1.0 §B.5).
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidPublicInput(_) => "INVALID_PUBLIC_INPUT",
            Self::UnregisteredInstance => "UNREGISTERED_INSTANCE",
            Self::InvalidRegistration(_) => "INVALID_REGISTRATION",
            Self::QuotaMismatch => "QUOTA_MISMATCH",
            Self::PolicyMismatch => "POLICY_MISMATCH",
            Self::ProofVerification(_) => "PROOF_INVALID",
            Self::StateConflict(_) => "STATE_CONFLICT",
            Self::Store(_) => "STORE_ERROR",
            Self::DuplicateRegistration => "DUPLICATE_REGISTRATION",
            Self::ScopeConflict(_) => "SCOPE_CONFLICT",
            Self::AttestationInvalid(_) => "ATTESTATION_INVALID",
            Self::AttestationBindingMismatch(_) => "ATTESTATION_BINDING_MISMATCH",
            Self::IdempotencyConflict(_) => "IDEMPOTENCY_CONFLICT",
            Self::ServiceConfig(_) => "SERVICE_CONFIG",
        }
    }
}

impl std::fmt::Display for E1Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}",
            self.code(),
            match self {
                Self::InvalidPublicInput(d)
                | Self::InvalidRegistration(d)
                | Self::StateConflict(d)
                | Self::Store(d)
                | Self::ScopeConflict(d)
                | Self::AttestationInvalid(d)
                | Self::AttestationBindingMismatch(d)
                | Self::IdempotencyConflict(d)
                | Self::ServiceConfig(d)
                | Self::ProofVerification(d) => d.clone(),
                Self::UnregisteredInstance => "budget instance is not registered".to_owned(),
                Self::QuotaMismatch => "public Q differs from registered Q".to_owned(),
                Self::PolicyMismatch => "public P differs from registered policy".to_owned(),
                Self::DuplicateRegistration => "instance already registered".to_owned(),
            }
        )
    }
}
impl std::error::Error for E1Error {}

impl From<StoreError> for E1Error {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound => Self::UnregisteredInstance,
            StoreError::Duplicate => Self::DuplicateRegistration,
            StoreError::Conflict(detail) => Self::StateConflict(detail),
            StoreError::Encoding(detail) => Self::InvalidPublicInput(detail),
            StoreError::Sqlite(detail) => Self::Store(detail),
        }
    }
}

// --------------------------------------------------------------------------- // scope //

/// The eleven business fields of an Issuer-signed cross-layer binding record
/// (E.0 §3.2). `budget_id`/`period_id`/`P` are Pallas Fp hex strings; `Q` is a
/// uint32; digests are `sha256:` strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossLayerScopeFields {
    pub global_budget_id: String,
    pub lease_id: String,
    pub period_id_hex: String,
    pub budget_id_hex: String,
    pub online_lease_grant_digest: String,
    pub metering_policy_digest: String,
    pub registration_authorization_digest: String,
}

/// Full signed envelope of a cross-layer binding record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossLayerScopeBindingRecord {
    pub version: u64,
    pub issuer_id: String,
    pub global_budget_id: String,
    pub lease_id: String,
    pub online_lease_grant_digest: String,
    pub budget_id: String,
    pub period_id: String,
    pub q: u64,
    pub p: String,
    pub metering_policy_digest: String,
    pub registration_authorization_digest: String,
    pub signature_b64: String,
}

fn nonempty(value: &str, field: &str) -> Result<(), E1Error> {
    if value.is_empty() {
        return Err(E1Error::InvalidRegistration(format!(
            "{field} must be non-empty"
        )));
    }
    Ok(())
}

fn u32_number(value: &Value, field: &str) -> Result<u64, E1Error> {
    // JSON numbers: reject bool / float / negative / out of range. serde_json
    // stores integers as u64 or i64 only.
    let n = value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|i| u64::try_from(i).ok()))
        .ok_or_else(|| E1Error::InvalidRegistration(format!("{field} must be a uint32 number")))?;
    if n == 0 || n > MAX_UINT32 {
        return Err(E1Error::InvalidRegistration(format!(
            "{field} outside [1, 2^32-1]"
        )));
    }
    Ok(n)
}

impl CrossLayerScopeBindingRecord {
    /// Parse from JSON with strict field set / types / formats. Does NOT verify
    /// the signature (that requires the trusted Issuer key in `register_e1`).
    pub fn parse(value: &Value) -> Result<Self, E1Error> {
        let obj = value.as_object().ok_or_else(|| {
            E1Error::InvalidRegistration("binding record must be an object".into())
        })?;
        const F: [&str; 12] = [
            "version",
            "issuer_id",
            "global_budget_id",
            "lease_id",
            "online_lease_grant_digest",
            "budget_id",
            "period_id",
            "Q",
            "P",
            "metering_policy_digest",
            "registration_authorization_digest",
            "signature_b64",
        ];
        validate_field_set(obj, &F, E1ErrorKind::Registration)?;
        let version = obj["version"]
            .as_u64()
            .ok_or_else(|| E1Error::InvalidRegistration("version must be integer 1".into()))?;
        if version != 1 {
            return Err(E1Error::InvalidRegistration(
                "unsupported binding record version".into(),
            ));
        }
        let get_str = |k: &str| -> Result<String, E1Error> {
            obj[k]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| E1Error::InvalidRegistration(format!("{k} must be a string")))
        };
        let issuer_id = get_str("issuer_id")?;
        let global_budget_id = get_str("global_budget_id")?;
        let lease_id = get_str("lease_id")?;
        let online_lease_grant_digest = get_str("online_lease_grant_digest")?;
        let budget_id = get_str("budget_id")?;
        let period_id = get_str("period_id")?;
        let p = get_str("P")?;
        let metering_policy_digest = get_str("metering_policy_digest")?;
        let registration_authorization_digest = get_str("registration_authorization_digest")?;
        let signature_b64 = get_str("signature_b64")?;
        let q = u32_number(&obj["Q"], "Q")?;
        nonempty(&issuer_id, "issuer_id")?;
        nonempty(&global_budget_id, "global_budget_id")?;
        nonempty(&lease_id, "lease_id")?;
        for digest in [
            &online_lease_grant_digest,
            &metering_policy_digest,
            &registration_authorization_digest,
        ] {
            if !is_sha256(digest) {
                return Err(E1Error::InvalidRegistration(
                    "invalid sha256 digest field".into(),
                ));
            }
        }
        for fp in [&budget_id, &period_id, &p] {
            if fp_from_hex_strict(fp).is_none() {
                return Err(E1Error::InvalidRegistration(
                    "invalid canonical Fp hex".into(),
                ));
            }
        }
        Ok(Self {
            version,
            issuer_id,
            global_budget_id,
            lease_id,
            online_lease_grant_digest,
            budget_id,
            period_id,
            q,
            p,
            metering_policy_digest,
            registration_authorization_digest,
            signature_b64,
        })
    }

    fn unsigned_payload(&self) -> Value {
        json!({
            "version": self.version,
            "issuer_id": self.issuer_id,
            "global_budget_id": self.global_budget_id,
            "lease_id": self.lease_id,
            "online_lease_grant_digest": self.online_lease_grant_digest,
            "budget_id": self.budget_id,
            "period_id": self.period_id,
            "Q": self.q,
            "P": self.p,
            "metering_policy_digest": self.metering_policy_digest,
            "registration_authorization_digest": self.registration_authorization_digest,
        })
    }

    /// `binding_record_digest = canonical_digest(domain, unsigned_payload)`.
    pub fn digest(&self) -> Result<String, E1Error> {
        canonical_digest(CROSS_LAYER_SCOPE_DOMAIN, &self.unsigned_payload())
            .map_err(|e| E1Error::InvalidRegistration(e.to_string()))
    }

    fn verify_signature(&self, issuer: &VerifyingKey) -> Result<(), E1Error> {
        let message =
            json!({"domain": CROSS_LAYER_SCOPE_DOMAIN, "payload": self.unsigned_payload()});
        let bytes = canonical_json_bytes(&message)
            .map_err(|e| E1Error::InvalidRegistration(e.to_string()))?;
        let sig = decode_signature(&self.signature_b64)?;
        issuer
            .verify(&bytes, &sig)
            .map_err(|_| E1Error::InvalidRegistration("Issuer scope signature invalid".into()))
    }

    fn scope_fields(&self) -> CrossLayerScopeFields {
        CrossLayerScopeFields {
            global_budget_id: self.global_budget_id.clone(),
            lease_id: self.lease_id.clone(),
            period_id_hex: self.period_id.clone(),
            budget_id_hex: self.budget_id.clone(),
            online_lease_grant_digest: self.online_lease_grant_digest.clone(),
            metering_policy_digest: self.metering_policy_digest.clone(),
            registration_authorization_digest: self.registration_authorization_digest.clone(),
        }
    }
}

// --------------------------------------------------------------------------- // helpers //

#[derive(Clone, Copy)]
enum E1ErrorKind {
    Registration,
    Attestation,
    Receipt,
}

fn validate_field_set(
    obj: &Map<String, Value>,
    allowed: &[&str],
    kind: E1ErrorKind,
) -> Result<(), E1Error> {
    if obj.len() != allowed.len() || allowed.iter().any(|k| !obj.contains_key(*k)) {
        let msg = "field set does not match schema".to_owned();
        return Err(match kind {
            E1ErrorKind::Registration => E1Error::InvalidRegistration(msg),
            E1ErrorKind::Attestation => E1Error::AttestationInvalid(msg),
            E1ErrorKind::Receipt => E1Error::IdempotencyConflict(msg),
        });
    }
    Ok(())
}

fn decode_signature(signature_b64: &str) -> Result<Signature, E1Error> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|_| E1Error::AttestationInvalid("signature_b64 is not valid base64".into()))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| E1Error::AttestationInvalid("signature must be 64 bytes".into()))?;
    Ok(Signature::from_bytes(&arr))
}

pub(crate) fn decode_public_key(key_b64: &str) -> Result<VerifyingKey, E1Error> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| E1Error::ServiceConfig("public key is not valid base64".into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| E1Error::ServiceConfig("public key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| E1Error::ServiceConfig("public key is not a valid Ed25519 key".into()))
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --------------------------------------------------------------------------- // attestation //

/// Verified fields extracted from a Metering Attestation. The object itself is
/// never trusted until Ed25519 verification + field binding succeed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub operation_id: String,
    pub binding_digest: String,
    pub executor_authorization_digest: String,
    pub arguments_digest: String,
    pub tool_name: String,
    pub tool_schema_hash: String,
    pub global_budget_id: String,
    pub lease_id: String,
    pub budget_id: Fp,
    pub period_id: Fp,
    pub q: u64,
    pub p: Fp,
    pub c: u64,
    pub metering_policy_digest: String,
    pub metering_quote_digest: String,
}

/// Verify an E1.2-python-signed Metering Attestation envelope.
///
/// `executor_keys` maps executor_id -> trusted public key (never from request).
/// `now` is the Coordinator's UTC Unix time (explicit for deterministic tests).
/// Checks: outer/inner field set, every field type/format, Ed25519 signature
/// over the domain-separated canonical message, quote digest recomputation, and
/// validity window. Cross-field binding to the live operation/scope is done by
/// `verify_attestation_binding` (called by `submit_transition_e1`).
pub fn verify_metering_attestation(
    envelope: &Value,
    executor_keys: &HashMap<String, VerifyingKey>,
    now: u64,
) -> Result<VerifiedAttestation, E1Error> {
    let outer = envelope.as_object().ok_or_else(|| {
        E1Error::AttestationInvalid("attestation envelope must be an object".into())
    })?;
    validate_field_set(
        outer,
        &["attestation", "signature_b64"],
        E1ErrorKind::Attestation,
    )?;
    let payload = outer["attestation"]
        .as_object()
        .ok_or_else(|| E1Error::AttestationInvalid("attestation must be an object".into()))?;
    validate_field_set(payload, &ATTESTATION_FIELDS, E1ErrorKind::Attestation)?;

    let version = payload["version"]
        .as_u64()
        .ok_or_else(|| E1Error::AttestationInvalid("version must be integer".into()))?;
    if version != 1 {
        return Err(E1Error::AttestationInvalid(
            "unsupported attestation version".into(),
        ));
    }
    let get_str = |k: &str| -> Result<String, E1Error> {
        payload[k]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| E1Error::AttestationInvalid(format!("{k} must be a string")))
    };
    let executor_id = get_str("executor_id")?;
    let operation_id = get_str("operation_id")?;
    let binding_digest = get_str("binding_digest")?;
    let executor_authorization_digest = get_str("executor_authorization_digest")?;
    let arguments_digest = get_str("arguments_digest")?;
    let canonicalization_version = get_str("canonicalization_version")?;
    let tool_name = get_str("tool_name")?;
    let tool_schema_hash = get_str("tool_schema_hash")?;
    let global_budget_id = get_str("global_budget_id")?;
    let lease_id = get_str("lease_id")?;
    let budget_id_hex = get_str("budget_id")?;
    let period_id_hex = get_str("period_id")?;
    let p_hex = get_str("P")?;
    let metering_policy_digest = get_str("metering_policy_digest")?;
    let signature_b64 = outer["signature_b64"]
        .as_str()
        .ok_or_else(|| E1Error::AttestationInvalid("signature_b64 must be a string".into()))?;

    for v in [
        &executor_id,
        &operation_id,
        &canonicalization_version,
        &tool_name,
        &global_budget_id,
        &lease_id,
    ] {
        nonempty(v, "string field")?;
    }
    for d in [
        &binding_digest,
        &executor_authorization_digest,
        &arguments_digest,
        &tool_schema_hash,
        &metering_policy_digest,
    ] {
        if !is_sha256(d) {
            return Err(E1Error::AttestationInvalid(
                "invalid sha256 digest field".into(),
            ));
        }
    }
    let budget_id = fp_from_hex_strict(&budget_id_hex)
        .ok_or_else(|| E1Error::AttestationInvalid("budget_id is not canonical Fp hex".into()))?;
    let period_id = fp_from_hex_strict(&period_id_hex)
        .ok_or_else(|| E1Error::AttestationInvalid("period_id is not canonical Fp hex".into()))?;
    let p = fp_from_hex_strict(&p_hex)
        .ok_or_else(|| E1Error::AttestationInvalid("P is not canonical Fp hex".into()))?;
    // Q and c are JSON uint32 numbers (NOT Fp hex here). Reject bool/float/zero/overflow.
    let q = u32_number(&payload["Q"], "Q").map_err(|_| {
        E1Error::AttestationInvalid("Q must be a nonzero uint32 JSON number".into())
    })?;
    let c = u32_number(&payload["c"], "c").map_err(|_| {
        E1Error::AttestationInvalid("c must be a nonzero uint32 JSON number".into())
    })?;
    let issued_at = payload["issued_at"]
        .as_u64()
        .ok_or_else(|| E1Error::AttestationInvalid("issued_at must be integer".into()))?;
    let expires_at = payload["expires_at"]
        .as_u64()
        .ok_or_else(|| E1Error::AttestationInvalid("expires_at must be integer".into()))?;
    if issued_at == 0 || issued_at >= expires_at {
        return Err(E1Error::AttestationInvalid(
            "invalid validity interval".into(),
        ));
    }
    if now < issued_at || now >= expires_at {
        return Err(E1Error::AttestationInvalid(
            "attestation is outside validity window".into(),
        ));
    }

    // Trusted executor key lookup: unknown id / wrong key both rejected.
    let vk = executor_keys
        .get(&executor_id)
        .ok_or_else(|| E1Error::AttestationInvalid("unknown executor_id".into()))?;
    let message = json!({"domain": ATTESTATION_DOMAIN, "payload": payload});
    let message_bytes =
        canonical_json_bytes(&message).map_err(|e| E1Error::AttestationInvalid(e.to_string()))?;
    let sig = decode_signature(signature_b64)?;
    vk.verify(&message_bytes, &sig)
        .map_err(|_| E1Error::AttestationInvalid("Executor signature invalid".into()))?;

    // Recompute the quote digest from the SAME payload; never trust a caller value.
    let quote = canonical_digest(ATTESTATION_DOMAIN, &Value::Object(payload.clone()))
        .map_err(|e| E1Error::AttestationInvalid(e.to_string()))?;

    Ok(VerifiedAttestation {
        operation_id,
        binding_digest,
        executor_authorization_digest,
        arguments_digest,
        tool_name,
        tool_schema_hash,
        global_budget_id,
        lease_id,
        budget_id,
        period_id,
        q,
        p,
        c,
        metering_policy_digest,
        metering_quote_digest: quote,
    })
}

/// Bind an already signature-verified attestation to the current operation and
/// the registered cross-layer scope. This is E1.3's binding boundary; the full
/// D10 authorization-chain closure is E1.4/E1.5.
#[allow(clippy::too_many_arguments)]
pub fn verify_attestation_binding(
    att: &VerifiedAttestation,
    expected_operation_id: &str,
    expected_binding_digest: &str,
    scope: &CrossLayerScopeFields,
    scope_budget_id: &Fp,
    scope_period_id: &Fp,
    scope_q: &Fp,
    scope_p: &Fp,
    instance_cost: &Fp,
) -> Result<(), E1Error> {
    if att.operation_id != expected_operation_id {
        return Err(E1Error::AttestationBindingMismatch(
            "operation_id mismatch".into(),
        ));
    }
    if att.binding_digest != expected_binding_digest {
        return Err(E1Error::AttestationBindingMismatch(
            "binding_digest mismatch".into(),
        ));
    }
    if att.global_budget_id != scope.global_budget_id || att.lease_id != scope.lease_id {
        return Err(E1Error::AttestationBindingMismatch(
            "D10 scope identifiers mismatch".into(),
        ));
    }
    if att.budget_id != *scope_budget_id || att.period_id != *scope_period_id {
        return Err(E1Error::AttestationBindingMismatch(
            "budget_id/period_id mismatch".into(),
        ));
    }
    if att.p != *scope_p {
        return Err(E1Error::AttestationBindingMismatch(
            "P mismatch vs registered scope".into(),
        ));
    }
    if att.metering_policy_digest != scope.metering_policy_digest {
        return Err(E1Error::AttestationBindingMismatch(
            "metering_policy_digest mismatch".into(),
        ));
    }
    // Q: attestation JSON uint32 vs registered Fp (strict convert Fp -> u32).
    let scope_q_u32 = fp_hex_to_u32(&fp_to_hex(scope_q))
        .map_err(|e| E1Error::AttestationBindingMismatch(format!("registered Q invalid: {e}")))?;
    if att.q != scope_q_u32 as u64 {
        return Err(E1Error::AttestationBindingMismatch(
            "Q mismatch vs registered quota".into(),
        ));
    }
    if att.p != *scope_p {
        return Err(E1Error::AttestationBindingMismatch("P mismatch".into()));
    }
    // c: attestation uint32 vs instance[3] Fp hex, both strictly converted.
    let cost_u32 = fp_hex_to_u32(&fp_to_hex(instance_cost))
        .map_err(|e| E1Error::InvalidPublicInput(format!("instance c invalid: {e}")))?;
    if att.c != cost_u32 as u64 {
        return Err(E1Error::AttestationBindingMismatch(
            "c mismatch vs instance[3]".into(),
        ));
    }
    Ok(())
}

// --------------------------------------------------------------------------- // receipt //

/// Complete E1TransitionReceipt. C-stage five-field `TransitionReceipt` is
/// untouched; this is a new, additive eleven-field structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E1TransitionReceipt {
    pub operation_id: String,
    pub binding_digest: String,
    pub metering_quote_digest: String,
    pub budget_id: String,
    pub period_id: String,
    pub state_version: u64,
    pub new_commitment: String,
    pub nullifier: String,
    pub coordinator_key_id: String,
    pub transition_digest: String,
    pub coordinator_signature: String,
}

impl E1TransitionReceipt {
    fn unsigned_payload(&self) -> Value {
        json!({
            "operation_id": self.operation_id,
            "binding_digest": self.binding_digest,
            "metering_quote_digest": self.metering_quote_digest,
            "budget_id": self.budget_id,
            "period_id": self.period_id,
            "state_version": self.state_version,
            "new_commitment": self.new_commitment,
            "nullifier": self.nullifier,
            "coordinator_key_id": self.coordinator_key_id,
        })
    }

    /// `D_T = canonical_digest(RECEIPT_DOMAIN, unsigned_payload)`; excludes
    /// transition_digest and coordinator_signature (no circular dependency).
    pub fn compute_digest(&self) -> Result<String, E1Error> {
        canonical_digest(RECEIPT_DOMAIN, &self.unsigned_payload())
            .map_err(|e| E1Error::Store(e.to_string()))
    }

    fn sign_message(digest: &str) -> Value {
        json!({"domain": RECEIPT_SIGN_DOMAIN, "transition_digest": digest})
    }

    /// Build, digest and sign a receipt from CAS-produced final values. Called
    /// *inside* the commit transaction by `submit_transition_e1`.
    #[allow(clippy::too_many_arguments)]
    fn build_and_sign(
        operation_id: &str,
        binding_digest: &str,
        metering_quote_digest: &str,
        budget_id: &Fp,
        period_id: &Fp,
        state_version: u64,
        new_commitment: &Fp,
        nullifier: &Fp,
        coordinator_key_id: &str,
        signing_key: &SigningKey,
    ) -> Result<Self, E1Error> {
        let mut receipt = Self {
            operation_id: operation_id.to_owned(),
            binding_digest: binding_digest.to_owned(),
            metering_quote_digest: metering_quote_digest.to_owned(),
            budget_id: fp_to_hex(budget_id),
            period_id: fp_to_hex(period_id),
            state_version,
            new_commitment: fp_to_hex(new_commitment),
            nullifier: fp_to_hex(nullifier),
            coordinator_key_id: coordinator_key_id.to_owned(),
            transition_digest: String::new(),
            coordinator_signature: String::new(),
        };
        let digest = receipt.compute_digest()?;
        let message = canonical_json_bytes(&Self::sign_message(&digest))
            .map_err(|e| E1Error::Store(e.to_string()))?;
        let sig = signing_key.sign(&message);
        receipt.transition_digest = digest;
        receipt.coordinator_signature =
            base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        Ok(receipt)
    }

    pub fn to_value(&self) -> Value {
        json!({
            "operation_id": self.operation_id,
            "binding_digest": self.binding_digest,
            "metering_quote_digest": self.metering_quote_digest,
            "budget_id": self.budget_id,
            "period_id": self.period_id,
            "state_version": self.state_version,
            "new_commitment": self.new_commitment,
            "nullifier": self.nullifier,
            "coordinator_key_id": self.coordinator_key_id,
            "transition_digest": self.transition_digest,
            "coordinator_signature": self.coordinator_signature,
        })
    }

    /// Canonical serialized bytes of the complete receipt (stored as blob).
    pub fn to_bytes(&self) -> Result<Vec<u8>, E1Error> {
        canonical_json_bytes(&self.to_value()).map_err(|e| E1Error::Store(e.to_string()))
    }

    /// Strict parse of a stored receipt blob with full field-set validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, E1Error> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|e| E1Error::IdempotencyConflict(format!("receipt blob is not JSON: {e}")))?;
        Self::from_value(&value)
    }

    pub fn from_value(value: &Value) -> Result<Self, E1Error> {
        let obj = value
            .as_object()
            .ok_or_else(|| E1Error::IdempotencyConflict("receipt must be an object".into()))?;
        validate_field_set(obj, &RECEIPT_FULL_FIELDS, E1ErrorKind::Receipt)?;
        let get_str = |k: &str| -> Result<String, E1Error> {
            obj[k]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| E1Error::IdempotencyConflict(format!("{k} must be a string")))
        };
        let state_version = obj["state_version"]
            .as_u64()
            .ok_or_else(|| E1Error::IdempotencyConflict("state_version must be integer".into()))?;
        let receipt = Self {
            operation_id: get_str("operation_id")?,
            binding_digest: get_str("binding_digest")?,
            metering_quote_digest: get_str("metering_quote_digest")?,
            budget_id: get_str("budget_id")?,
            period_id: get_str("period_id")?,
            state_version,
            new_commitment: get_str("new_commitment")?,
            nullifier: get_str("nullifier")?,
            coordinator_key_id: get_str("coordinator_key_id")?,
            transition_digest: get_str("transition_digest")?,
            coordinator_signature: get_str("coordinator_signature")?,
        };
        // Fp and digest formats.
        for fp in [
            &receipt.budget_id,
            &receipt.period_id,
            &receipt.new_commitment,
            &receipt.nullifier,
        ] {
            if fp_from_hex_strict(fp).is_none() {
                return Err(E1Error::IdempotencyConflict(
                    "receipt contains non-canonical Fp hex".into(),
                ));
            }
        }
        for d in [
            &receipt.binding_digest,
            &receipt.metering_quote_digest,
            &receipt.transition_digest,
        ] {
            if !is_sha256(d) {
                return Err(E1Error::IdempotencyConflict(
                    "receipt contains invalid digest".into(),
                ));
            }
        }
        Ok(receipt)
    }

    /// Re-verify digest, Coordinator signature and DB cross-field consistency.
    /// SQLite is only a recovery medium, never the authenticity root.
    pub fn verify(
        &self,
        coordinator_public_keys: &HashMap<String, VerifyingKey>,
        op_row: &E1OperationRow,
        expected_binding_digest: &str,
        expected_metering_quote_digest: &str,
    ) -> Result<(), E1Error> {
        if self.compute_digest()? != self.transition_digest {
            return Err(E1Error::IdempotencyConflict(
                "transition_digest mismatch".into(),
            ));
        }
        let vk = coordinator_public_keys
            .get(&self.coordinator_key_id)
            .ok_or_else(|| E1Error::IdempotencyConflict("unknown coordinator_key_id".into()))?;
        let message = canonical_json_bytes(&Self::sign_message(&self.transition_digest))
            .map_err(|e| E1Error::Store(e.to_string()))?;
        let sig = decode_signature(&self.coordinator_signature).map_err(|_| {
            E1Error::IdempotencyConflict("invalid coordinator signature encoding".into())
        })?;
        vk.verify(&message, &sig)
            .map_err(|_| E1Error::IdempotencyConflict("coordinator signature invalid".into()))?;
        // Cross-check receipt against the immutable operation row.
        if self.operation_id != op_row.operation_id
            || self.binding_digest != op_row.binding_digest
            || self.metering_quote_digest != op_row.metering_quote_digest
            || self.budget_id != op_row.budget_id
            || self.period_id != op_row.period_id
            || self.nullifier != op_row.nullifier
            || self.state_version != op_row.committed_version
            || self.new_commitment != op_row.new_commitment
            || self.transition_digest != op_row.transition_digest
        {
            return Err(E1Error::IdempotencyConflict(
                "receipt does not match stored operation".into(),
            ));
        }
        if expected_binding_digest != self.binding_digest {
            return Err(E1Error::IdempotencyConflict(
                "expected binding_digest mismatch".into(),
            ));
        }
        if expected_metering_quote_digest != self.metering_quote_digest {
            return Err(E1Error::IdempotencyConflict(
                "expected metering_quote_digest mismatch".into(),
            ));
        }
        Ok(())
    }
}

// --------------------------------------------------------------------------- // coordinator //

/// Trust configuration for the E1 Coordinator. All keys come from trusted
/// configuration, never from a request.
#[derive(Clone, Debug)]
pub struct E1CoordinatorConfig {
    pub issuer_id: String,
    pub issuer_public_key: VerifyingKey,
    pub executor_public_keys: HashMap<String, VerifyingKey>,
    pub coordinator_key_id: String,
    pub coordinator_signing_key: SigningKey,
    pub coordinator_public_keys: HashMap<String, VerifyingKey>,
}

/// Additive E1 Coordinator. Holds a stable signing key; a fresh instance can be
/// created after a process restart and still verify previously issued receipts.
#[derive(Clone)]
pub struct E1Coordinator {
    config: E1CoordinatorConfig,
    db_path: PathBuf,
    verifier: std::sync::Arc<ProofVerifier>,
    crash_point: Option<CrashPoint>,
}

impl E1Coordinator {
    pub fn new(config: E1CoordinatorConfig, db_path: PathBuf) -> Result<Self, E1Error> {
        // Startup invariant: signing key derives the configured public key.
        let derived = config.coordinator_signing_key.verifying_key();
        let configured = config
            .coordinator_public_keys
            .get(&config.coordinator_key_id)
            .ok_or_else(|| {
                E1Error::ServiceConfig("coordinator_key_id not in public key map".into())
            })?;
        if derived != *configured {
            return Err(E1Error::ServiceConfig(
                "signing key does not match configured public key".into(),
            ));
        }
        Ok(Self {
            config,
            db_path,
            verifier: std::sync::Arc::new(ProofVerifier::new_experimental()),
            crash_point: None,
        })
    }

    /// Test-only: set a crash injection point on this in-process coordinator.
    /// NOT exposed as a JSON Lines request parameter.
    pub fn set_crash_point(&mut self, point: Option<CrashPoint>) {
        self.crash_point = point;
    }

    pub fn config(&self) -> &E1CoordinatorConfig {
        &self.config
    }

    /// Register an Issuer-signed cross-layer scope together with the D11 budget
    /// instance, enforcing the SQLite UNIQUE(scope) constraint.
    pub fn register_e1(
        &self,
        binding_record: &CrossLayerScopeBindingRecord,
        registration_authorization: &[u8],
    ) -> Result<(), E1Error> {
        // 1. Issuer signature + trusted issuer_id.
        binding_record.verify_signature(&self.config.issuer_public_key)?;
        if binding_record.issuer_id != self.config.issuer_id {
            return Err(E1Error::InvalidRegistration("issuer_id not trusted".into()));
        }
        // 2. Decode + verify the C-stage registration authorization (unchanged).
        let auth = RegistrationAuthorization::decode(registration_authorization)
            .map_err(|e| E1Error::InvalidRegistration(format!("{e}")))?;
        auth.verify(&self.config.issuer_public_key)
            .map_err(|e| E1Error::InvalidRegistration(format!("{e}")))?;
        // 3. Authorization immutable fields must match the binding record.
        let budget_id = fp_from_hex_strict(&binding_record.budget_id)
            .ok_or_else(|| E1Error::InvalidRegistration("budget_id Fp".into()))?;
        let period_id = fp_from_hex_strict(&binding_record.period_id)
            .ok_or_else(|| E1Error::InvalidRegistration("period_id Fp".into()))?;
        let q = Fp::from(binding_record.q);
        let p = fp_from_hex_strict(&binding_record.p)
            .ok_or_else(|| E1Error::InvalidRegistration("P Fp".into()))?;
        if auth.fields.budget_id != budget_id
            || auth.fields.period_id != period_id
            || auth.fields.quota != q
            || auth.fields.policy != p
        {
            return Err(E1Error::InvalidRegistration(
                "authorization fields do not match binding record".into(),
            ));
        }
        // 4. registration_authorization_digest over the RAW authorization bytes
        //    (no JSON re-encoding), domain-free SHA-256 as in C stage.
        let raw_digest = format!(
            "sha256:{}",
            hex_lower(&sha2::Sha256::digest(registration_authorization))
        );
        if raw_digest != binding_record.registration_authorization_digest {
            return Err(E1Error::InvalidRegistration(
                "registration_authorization_digest mismatch".into(),
            ));
        }
        // 5. metering_policy_digest format already checked at parse time.
        let binding_digest = binding_record.digest()?;
        let mut store = StateStore::open(&self.db_path).map_err(StoreError::from)?;
        store
            .register_cross_layer_scope(
                &auth.fields,
                &auth.encode(),
                &binding_record.scope_fields(),
                &binding_digest,
            )
            .map_err(|e| match e {
                StoreError::Duplicate => E1Error::DuplicateRegistration,
                StoreError::Conflict(d) => E1Error::ScopeConflict(d),
                other => E1Error::from(other),
            })
    }

    /// Verify proof + attestation + scope binding, then atomically commit the
    /// E1 state transition with a signed receipt in the SAME SQLite transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_transition_e1(
        &self,
        proof_b64: &str,
        instance_hex: &[String; INSTANCE_ROWS],
        attestation: &Value,
        expected_metering_quote_digest: &str,
        operation_id: &str,
        binding_digest: &str,
        now: u64,
    ) -> Result<E1TransitionReceipt, E1Error> {
        // 1. Public input format + strict uint32 for Q/c (hex -> u32).
        let instance = parse_instance(instance_hex)?;
        let quota = fp_hex_to_u32(&instance_hex[2])
            .map_err(|e| E1Error::InvalidPublicInput(format!("Q: {e}")))?;
        let cost = fp_hex_to_u32(&instance_hex[3])
            .map_err(|e| E1Error::InvalidPublicInput(format!("c: {e}")))?;
        let _ = (quota, cost);

        // 2. Instance registered + stored authorization revalidated (reuse C checks).
        let store = StateStore::open(&self.db_path).map_err(StoreError::from)?;
        let row = store
            .get_instance(&instance[0], &instance[1])
            .map_err(StoreError::from)?
            .ok_or(E1Error::UnregisteredInstance)?;
        StateStore::validate_stored_quota(&row)
            .map_err(|e| E1Error::InvalidRegistration(e.to_string()))?;
        let stored_auth = RegistrationAuthorization::decode(&row.authorization_bytes)
            .map_err(|e| E1Error::InvalidRegistration(format!("{e}")))?;
        stored_auth
            .verify(&self.config.issuer_public_key)
            .map_err(|e| E1Error::InvalidRegistration(format!("{e}")))?;
        if stored_auth.fields.budget_id != row.budget_id
            || stored_auth.fields.period_id != row.period_id
            || stored_auth.fields.quota != row.quota
            || stored_auth.fields.policy != row.policy
        {
            return Err(E1Error::InvalidRegistration(
                "stored authorization mismatch".into(),
            ));
        }
        if instance[2] != row.quota {
            return Err(E1Error::QuotaMismatch);
        }
        if instance[7] != row.policy {
            return Err(E1Error::PolicyMismatch);
        }

        // 3. Cross-layer scope must be registered for this instance.
        let scope = store
            .get_cross_layer_scope(&instance[0], &instance[1])
            .map_err(StoreError::from)?
            .ok_or(E1Error::UnregisteredInstance)?;

        // 4. Verify the Python-signed Metering Attestation.
        let att = verify_metering_attestation(attestation, &self.config.executor_public_keys, now)?;
        // Quote digest supplied by caller must equal the recomputed one.
        if expected_metering_quote_digest != att.metering_quote_digest {
            return Err(E1Error::AttestationInvalid(
                "metering_quote_digest mismatch".into(),
            ));
        }
        verify_attestation_binding(
            &att,
            operation_id,
            binding_digest,
            &scope,
            &instance[0],
            &instance[1],
            &instance[2],
            &instance[7],
            &instance[3],
        )?;

        // 5. Real Halo2 verification, no MockProver / no verified flag.
        let proof = proof_b64_decode(proof_b64)
            .map_err(|e| E1Error::InvalidPublicInput(format!("proof base64: {e}")))?;
        self.verifier
            .verify_proof(&proof, &instance)
            .map_err(|e: ProofVerifyError| E1Error::ProofVerification(e.to_string()))?;

        // 6. Atomic commit: CAS + receipt build/sign + operation row in one tx.
        let signing_key = self.config.coordinator_signing_key.clone();
        let key_id = self.config.coordinator_key_id.clone();
        let op_budget = instance[0];
        let op_period = instance[1];
        let c_old = instance[4];
        let c_new = instance[5];
        let nullifier = instance[6];
        let quote = att.metering_quote_digest.clone();
        let op_id = operation_id.to_owned();
        let bind = binding_digest.to_owned();
        let mut store = StateStore::open(&self.db_path).map_err(StoreError::from)?;
        let outcome = store
            .cas_commit_e1(
                &E1OperationParams {
                    operation_id: &op_id,
                    budget_id: &op_budget,
                    period_id: &op_period,
                    binding_digest: &bind,
                    metering_quote_digest: &quote,
                },
                &c_old,
                &c_new,
                &nullifier,
                self.crash_point,
                |version, new_commitment, nullifier| {
                    let receipt = E1TransitionReceipt::build_and_sign(
                        &op_id,
                        &bind,
                        &quote,
                        &op_budget,
                        &op_period,
                        version,
                        new_commitment,
                        nullifier,
                        &key_id,
                        &signing_key,
                    )
                    .map_err(|e| StoreError::Encoding(e.to_string()))?;
                    let blob = receipt
                        .to_bytes()
                        .map_err(|e| StoreError::Encoding(e.to_string()))?;
                    Ok(E1BuiltReceipt {
                        transition_digest: receipt.transition_digest.clone(),
                        receipt_blob: blob,
                    })
                },
            )
            .map_err(|e| match e {
                StoreError::Conflict(d) if d.contains("operation_id reused") => {
                    E1Error::IdempotencyConflict(d)
                }
                other => E1Error::from(other),
            })?;

        // 7. Return the exact stored receipt bytes (idempotent path too).
        let blob = match outcome {
            E1CommitOutcome::Committed { receipt_blob, .. }
            | E1CommitOutcome::Idempotent { receipt_blob, .. } => receipt_blob,
        };
        E1TransitionReceipt::from_bytes(&blob)
    }

    /// Idempotent recovery: read the stored receipt blob verbatim, re-verify
    /// digest + signature + DB fields, and return it. Never rebuild a receipt.
    pub fn get_operation(
        &self,
        operation_id: &str,
        expected_binding_digest: &str,
        expected_metering_quote_digest: &str,
    ) -> Result<Option<E1TransitionReceipt>, E1Error> {
        let store = StateStore::open(&self.db_path).map_err(StoreError::from)?;
        let row = store
            .get_operation_row(operation_id)
            .map_err(StoreError::from)?;
        let Some(row) = row else {
            return Ok(None);
        };
        // The blob is the authenticity subject; DB fields are cross-checks only.
        let receipt = E1TransitionReceipt::from_bytes(&row.receipt_blob)?;
        receipt.verify(
            &self.config.coordinator_public_keys,
            &row,
            expected_binding_digest,
            expected_metering_quote_digest,
        )?;
        Ok(Some(receipt))
    }
}

// --------------------------------------------------------------------------- // parse //

fn parse_instance(hex: &[String; INSTANCE_ROWS]) -> Result<[Fp; INSTANCE_ROWS], E1Error> {
    let mut out = [Fp::ZERO; INSTANCE_ROWS];
    for (i, cell) in hex.iter().enumerate() {
        out[i] = fp_from_hex_strict(cell).ok_or_else(|| {
            E1Error::InvalidPublicInput(format!("instance[{i}] is not canonical Fp hex"))
        })?;
    }
    Ok(out)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// --------------------------------------------------------------------------- // jsonl service //

/// A JSON Lines request envelope (E1.0 §B.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceRequest {
    pub request_id: String,
    pub method: String,
    pub payload: Value,
}

/// Parse a single-line request with strict envelope field set.
pub fn parse_service_request(line: &str) -> Result<ServiceRequest, E1Error> {
    let value: Value = serde_json::from_str(line)
        .map_err(|e| E1Error::InvalidPublicInput(format!("invalid request JSON: {e}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| E1Error::InvalidPublicInput("request must be an object".into()))?;
    validate_field_set(
        obj,
        &["request_id", "method", "payload"],
        E1ErrorKind::Registration,
    )?;
    let request_id = obj["request_id"]
        .as_str()
        .ok_or_else(|| E1Error::InvalidPublicInput("request_id must be a string".into()))?
        .to_owned();
    let method = obj["method"]
        .as_str()
        .ok_or_else(|| E1Error::InvalidPublicInput("method must be a string".into()))?
        .to_owned();
    Ok(ServiceRequest {
        request_id,
        method,
        payload: obj["payload"].clone(),
    })
}

/// Handle one parsed request against a coordinator. Returns the result object
/// on success, or an E1Error mapped to a stable service code by the caller.
/// `prove` uses the real prove_experimental() over a witness supplied in the
/// payload; it never fabricates a proof.
pub fn handle_request(
    coordinator: &E1Coordinator,
    request: &ServiceRequest,
) -> Result<Value, E1Error> {
    match request.method.as_str() {
        "health" => Ok(json!({"status": "ok", "service": "d11-e1-coordinator"})),
        "register_e1" => {
            let payload = request
                .payload
                .as_object()
                .ok_or_else(|| E1Error::InvalidRegistration("payload must be an object".into()))?;
            let binding_value = payload
                .get("binding_record")
                .ok_or_else(|| E1Error::InvalidRegistration("binding_record missing".into()))?;
            let record = CrossLayerScopeBindingRecord::parse(binding_value)?;
            let auth_b64 = payload
                .get("registration_authorization_b64")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    E1Error::InvalidRegistration("registration_authorization_b64 missing".into())
                })?;
            let auth_bytes = base64::engine::general_purpose::STANDARD
                .decode(auth_b64)
                .map_err(|_| {
                    E1Error::InvalidRegistration("registration authorization not base64".into())
                })?;
            coordinator.register_e1(&record, &auth_bytes)?;
            Ok(json!({"registered": true}))
        }
        "prove" => handle_prove(&request.payload),
        "submit_transition_e1" => {
            let p = request
                .payload
                .as_object()
                .ok_or_else(|| E1Error::InvalidPublicInput("payload must be an object".into()))?;
            let proof_b64 = p
                .get("proof_b64")
                .and_then(|v| v.as_str())
                .ok_or_else(|| E1Error::InvalidPublicInput("proof_b64 missing".into()))?;
            let instance_val = p
                .get("instance")
                .ok_or_else(|| E1Error::InvalidPublicInput("instance missing".into()))?;
            let instance = parse_instance_array(instance_val)?;
            let attestation = p.get("metering_attestation").ok_or_else(|| {
                E1Error::AttestationInvalid("metering_attestation missing".into())
            })?;
            let quote = p
                .get("metering_quote_digest")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    E1Error::AttestationInvalid("metering_quote_digest missing".into())
                })?;
            let operation_id = p
                .get("operation_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    E1Error::AttestationBindingMismatch("operation_id missing".into())
                })?;
            let binding_digest = p
                .get("binding_digest")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    E1Error::AttestationBindingMismatch("binding_digest missing".into())
                })?;
            let receipt = coordinator.submit_transition_e1(
                proof_b64,
                &instance,
                attestation,
                quote,
                operation_id,
                binding_digest,
                now_unix(),
            )?;
            Ok(receipt.to_value())
        }
        "get_operation" => {
            let p = request
                .payload
                .as_object()
                .ok_or_else(|| E1Error::InvalidPublicInput("payload must be an object".into()))?;
            let operation_id = p
                .get("operation_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| E1Error::InvalidPublicInput("operation_id missing".into()))?;
            let binding = p
                .get("expected_binding_digest")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    E1Error::InvalidPublicInput("expected_binding_digest missing".into())
                })?;
            let quote = p
                .get("expected_metering_quote_digest")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    E1Error::InvalidPublicInput("expected_metering_quote_digest missing".into())
                })?;
            match coordinator.get_operation(operation_id, binding, quote)? {
                Some(receipt) => Ok(receipt.to_value()),
                None => Ok(Value::Null),
            }
        }
        other => Err(E1Error::InvalidPublicInput(format!(
            "unknown method: {other}"
        ))),
    }
}

fn parse_instance_array(value: &Value) -> Result<[String; INSTANCE_ROWS], E1Error> {
    let arr = value
        .as_array()
        .ok_or_else(|| E1Error::InvalidPublicInput("instance must be an array".into()))?;
    if arr.len() != INSTANCE_ROWS {
        return Err(E1Error::InvalidPublicInput(format!(
            "instance must have {INSTANCE_ROWS} rows"
        )));
    }
    let mut out = Vec::with_capacity(INSTANCE_ROWS);
    for cell in arr {
        out.push(
            cell.as_str()
                .ok_or_else(|| {
                    E1Error::InvalidPublicInput("instance rows must be Fp hex strings".into())
                })?
                .to_owned(),
        );
    }
    Ok(out.try_into().expect("length checked"))
}

/// `prove` builds a real Halo2 proof from a StateWitness supplied in the payload
/// via the frozen B.1 circuit; no alternative proving path is introduced.
fn handle_prove(payload: &Value) -> Result<Value, E1Error> {
    use crate::proof_verifier::prove_experimental;
    use d11_3_b_state_transition::StateWitness;

    let w = payload
        .as_object()
        .ok_or_else(|| E1Error::InvalidPublicInput("prove payload must be an object".into()))?;
    let get_fp = |k: &str| -> Result<Fp, E1Error> {
        let hex = w
            .get(k)
            .and_then(|v| v.as_str())
            .ok_or_else(|| E1Error::InvalidPublicInput(format!("{k} missing")))?;
        fp_from_hex_strict(hex)
            .ok_or_else(|| E1Error::InvalidPublicInput(format!("{k} is not canonical Fp hex")))
    };
    let get_u64 = |k: &str| -> Result<u64, E1Error> {
        w.get(k)
            .and_then(|v| v.as_u64())
            .ok_or_else(|| E1Error::InvalidPublicInput(format!("{k} must be an integer")))
    };
    let witness = StateWitness {
        budget_id: get_fp("budget_id")?,
        period_id: get_fp("period_id")?,
        quota: get_u64("quota")?,
        cost: get_u64("cost")?,
        u_old: get_u64("u_old")?,
        u_new: get_u64("u_new")?,
        slack: get_u64("slack")?,
        r_old: get_fp("r_old")?,
        r_new: get_fp("r_new")?,
        nf_secret: get_fp("nf_secret")?,
        policy: get_fp("policy")?,
    };
    let (proof, instance) = prove_experimental(&witness);
    let proof_b64 = crate::e1_encoding::proof_b64_encode(&proof)
        .map_err(|e| E1Error::InvalidPublicInput(e.to_string()))?;
    let instance_hex: Vec<String> = instance.iter().map(fp_to_hex).collect();
    Ok(json!({"proof_b64": proof_b64, "instance": instance_hex}))
}

/// Serialize a successful service response (single line, canonical JSON).
pub fn success_response(request_id: &str, result: &Value) -> Result<String, E1Error> {
    let value = json!({"request_id": request_id, "ok": true, "result": result});
    let bytes = canonical_json_bytes(&value).map_err(|e| E1Error::Store(e.to_string()))?;
    Ok(String::from_utf8(bytes).expect("canonical JSON is UTF-8"))
}

/// Serialize a failing service response with a stable error code.
pub fn error_response(request_id: &str, error: &E1Error) -> Result<String, E1Error> {
    let value = json!({
        "request_id": request_id,
        "ok": false,
        "error": {"code": error.code(), "message": error.to_string()},
    });
    let bytes = canonical_json_bytes(&value).map_err(|e| E1Error::Store(e.to_string()))?;
    Ok(String::from_utf8(bytes).expect("canonical JSON is UTF-8"))
}

// --------------------------------------------------------------------------- // service config //

/// Full service configuration parsed from a trusted on-disk JSON file. Private
/// signing keys live ONLY here — never in JSON Lines requests or CLI args.
pub struct E1ServiceConfig {
    pub coordinator: E1CoordinatorConfig,
    pub db_path: PathBuf,
}

fn decode_signing_key(key_b64: &str) -> Result<SigningKey, E1Error> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|_| E1Error::ServiceConfig("signing key not base64".into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| E1Error::ServiceConfig("signing key must be 32-byte seed".into()))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Parse a service config JSON value. Strict about required fields; all public
/// keys are decoded, and the coordinator signing/public-key consistency is
/// checked by [`E1Coordinator::new`].
pub fn parse_service_config(value: &Value) -> Result<E1ServiceConfig, E1Error> {
    let obj = value
        .as_object()
        .ok_or_else(|| E1Error::ServiceConfig("config must be an object".into()))?;
    let get_str = |k: &str| -> Result<String, E1Error> {
        obj.get(k)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or_else(|| E1Error::ServiceConfig(format!("{k} missing")))
    };
    let db_path = PathBuf::from(get_str("db_path")?);
    let issuer_id = get_str("issuer_id")?;
    let issuer_public_key = decode_public_key(&get_str("issuer_public_key_b64")?)?;
    let coordinator_key_id = get_str("coordinator_key_id")?;
    let coordinator_signing_key = decode_signing_key(&get_str("coordinator_signing_key_b64")?)?;

    let parse_key_map = |field: &str| -> Result<HashMap<String, VerifyingKey>, E1Error> {
        let map = obj
            .get(field)
            .and_then(|v| v.as_object())
            .ok_or_else(|| E1Error::ServiceConfig(format!("{field} missing")))?;
        let mut out = HashMap::new();
        for (id, v) in map {
            let b64 = v
                .as_str()
                .ok_or_else(|| E1Error::ServiceConfig(format!("{field}[{id}] must be a string")))?;
            out.insert(id.clone(), decode_public_key(b64)?);
        }
        Ok(out)
    };
    let executor_public_keys = parse_key_map("executor_public_keys")?;
    let coordinator_public_keys = parse_key_map("coordinator_public_keys")?;

    Ok(E1ServiceConfig {
        coordinator: E1CoordinatorConfig {
            issuer_id,
            issuer_public_key,
            executor_public_keys,
            coordinator_key_id,
            coordinator_signing_key,
            coordinator_public_keys,
        },
        db_path,
    })
}
