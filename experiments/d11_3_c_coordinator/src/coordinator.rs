//! D11.3-C Coordinator: registration, proof checking, replay protection and
//! atomic state update. This is an off-chain, single-process prototype; it is
//! not a distributed Coordinator and has no consensus or high availability.

use std::{path::PathBuf, sync::Arc};

use ed25519_dalek::VerifyingKey;
use halo2_proofs::pasta::Fp;

use crate::{
    fp_to_u64_checked,
    proof_verifier::{ProofVerifier, ProofVerifyError},
    registration::{RegistrationAuthorization, RegistrationError},
    state_store::{StateStore, StoreError},
    INSTANCE_ROWS, MAX_UINT32,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoordinatorError {
    /// Public input is malformed or outside the B.1 uint32 domain.
    InvalidPublicInput(String),
    /// No successful issuer-authorized registration for this instance key.
    UnregisteredInstance,
    /// Stored authorization is invalid, non-canonical or does not match the row.
    InvalidAuthorization(RegistrationError),
    /// Public Q does not equal the registered Q.
    QuotaMismatch,
    /// Public P does not equal the registered policy (D11.3-A scheme B).
    PolicyMismatch,
    /// Real Halo2 verification failed.
    ProofVerification(ProofVerifyError),
    /// Transaction-level CAS failure: stale C_old, reused N or write conflict.
    StateConflict(String),
    /// Storage failure.
    Store(StoreError),
    /// Duplicate registration for an existing `(budget_id, period_id)`.
    DuplicateRegistration,
}

impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPublicInput(detail) => write!(f, "invalid public input: {detail}"),
            Self::UnregisteredInstance => write!(f, "budget instance is not registered"),
            Self::InvalidAuthorization(detail) => write!(f, "invalid registration: {detail}"),
            Self::QuotaMismatch => write!(f, "public Q differs from registered Q"),
            Self::PolicyMismatch => write!(f, "public P differs from registered P"),
            Self::ProofVerification(detail) => write!(f, "{detail}"),
            Self::StateConflict(detail) => write!(f, "state conflict: {detail}"),
            Self::Store(detail) => write!(f, "{detail}"),
            Self::DuplicateRegistration => write!(f, "instance already registered"),
        }
    }
}

impl std::error::Error for CoordinatorError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionReceipt {
    pub budget_id: Fp,
    pub period_id: Fp,
    pub version: u64,
    pub new_commitment: Fp,
    pub nullifier: Fp,
}

/// Prototype Coordinator. A new SQLite connection is opened for each operation
/// so that genuinely concurrent callers contend on the database lock.
#[derive(Clone)]
pub struct Coordinator {
    issuer_vk: VerifyingKey,
    db_path: PathBuf,
    verifier: Arc<ProofVerifier>,
}

impl Coordinator {
    pub fn new(issuer_vk: VerifyingKey, db_path: PathBuf) -> Self {
        Self {
            issuer_vk,
            db_path,
            verifier: Arc::new(ProofVerifier::new_experimental()),
        }
    }

    /// Register an issuer-authorized initial state `C_0` with quota Q and
    /// policy P. Does not prove knowledge of the `C_0` opening (D11.3-A §4.1).
    pub fn register(
        &self,
        authorization: &RegistrationAuthorization,
    ) -> Result<(), CoordinatorError> {
        authorization
            .verify(&self.issuer_vk)
            .map_err(CoordinatorError::InvalidAuthorization)?;
        authorization
            .fields
            .validate()
            .map_err(CoordinatorError::InvalidAuthorization)?;
        let mut store = StateStore::open(&self.db_path).map_err(CoordinatorError::Store)?;
        store
            .register(&authorization.fields, &authorization.encode())
            .map_err(|error| match error {
                StoreError::Duplicate => CoordinatorError::DuplicateRegistration,
                other => CoordinatorError::Store(other),
            })
    }

    /// Accept one state-transition proof.
    ///
    /// Order follows the task package: parse public input, confirm registration
    /// and stored authorization validity, check Q and P, verify the real proof,
    /// then perform all state/nullifier checks again inside one SQLite
    /// `BEGIN IMMEDIATE` transaction and commit atomically.
    pub fn submit_transition(
        &self,
        proof: &[u8],
        instance: &[Fp; INSTANCE_ROWS],
    ) -> Result<TransitionReceipt, CoordinatorError> {
        // 1. Public input shape and uint32 domain for Q and c.
        let quota = fp_to_u64_checked(&instance[2]).ok_or_else(|| {
            CoordinatorError::InvalidPublicInput("Q does not fit uint32".to_owned())
        })?;
        let cost = fp_to_u64_checked(&instance[3]).ok_or_else(|| {
            CoordinatorError::InvalidPublicInput("c does not fit uint32".to_owned())
        })?;
        if quota == 0 || quota > MAX_UINT32 {
            return Err(CoordinatorError::InvalidPublicInput(
                "Q must satisfy 1 <= Q <= 2^32-1".to_owned(),
            ));
        }
        if cost == 0 || cost > MAX_UINT32 {
            return Err(CoordinatorError::InvalidPublicInput(
                "c must satisfy 1 <= c <= 2^32-1".to_owned(),
            ));
        }

        // 2. Instance must be registered and its stored authorization valid.
        let store = StateStore::open(&self.db_path).map_err(CoordinatorError::Store)?;
        let row = store
            .get_instance(&instance[0], &instance[1])
            .map_err(CoordinatorError::Store)?
            .ok_or(CoordinatorError::UnregisteredInstance)?;
        StateStore::validate_stored_quota(&row)?;
        let stored_authorization = RegistrationAuthorization::decode(&row.authorization_bytes)
            .map_err(CoordinatorError::InvalidAuthorization)?;
        stored_authorization
            .verify(&self.issuer_vk)
            .map_err(CoordinatorError::InvalidAuthorization)?;
        // The authorization binds C_0; after transitions the row's
        // current_commitment is C_n, so only the immutable registered fields
        // are compared here. C_0 itself is covered by the issuer signature.
        if stored_authorization.fields.budget_id != row.budget_id
            || stored_authorization.fields.period_id != row.period_id
            || stored_authorization.fields.quota != row.quota
            || stored_authorization.fields.policy != row.policy
        {
            return Err(CoordinatorError::InvalidAuthorization(
                RegistrationError::InvalidEncoding(
                    "stored authorization does not match row".to_owned(),
                ),
            ));
        }
        if !store
            .authorization_matches_row(&row, &stored_authorization.encode())
            .map_err(CoordinatorError::Store)?
        {
            return Err(CoordinatorError::InvalidAuthorization(
                RegistrationError::InvalidEncoding("stored authorization bytes changed".to_owned()),
            ));
        }

        // 3. Public Q and P must equal the registered values.
        if instance[2] != row.quota {
            return Err(CoordinatorError::QuotaMismatch);
        }
        if instance[7] != row.policy {
            return Err(CoordinatorError::PolicyMismatch);
        }

        // 4. Real Halo2 verification, outside the write transaction.
        self.verifier
            .verify_proof(proof, instance)
            .map_err(CoordinatorError::ProofVerification)?;

        // 5. BEGIN IMMEDIATE: recheck C_old and N, insert N, advance state.
        let mut store = StateStore::open(&self.db_path).map_err(CoordinatorError::Store)?;
        let version = store
            .cas_commit(
                &instance[0],
                &instance[1],
                &instance[4],
                &instance[5],
                &instance[6],
            )
            .map_err(|error| match error {
                StoreError::Conflict(detail) => CoordinatorError::StateConflict(detail),
                other => CoordinatorError::Store(other),
            })?;

        Ok(TransitionReceipt {
            budget_id: instance[0],
            period_id: instance[1],
            version,
            new_commitment: instance[5],
            nullifier: instance[6],
        })
    }
}
