//! SQLite persistence and the atomic state/nullifier commit for D11.3-C.
//!
//! The compare-and-swap runs in a single `BEGIN IMMEDIATE` transaction:
//! re-read current state, check `C_old`, check unused `N`, insert `N`, update
//! commitment and version. Any failure rolls the whole transaction back.

use std::{path::Path, time::Duration};

use halo2_proofs::pasta::Fp;
use rusqlite::{params, types::Type, Connection, OptionalExtension, TransactionBehavior};

use crate::{
    fp_from_hex, fp_to_hex, registration::RegistrationFields, CoordinatorError, MAX_UINT32,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    Sqlite(String),
    Encoding(String),
    NotFound,
    Duplicate,
    Conflict(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(detail) => write!(f, "sqlite error: {detail}"),
            Self::Encoding(detail) => write!(f, "field encoding error: {detail}"),
            Self::NotFound => write!(f, "registration not found"),
            Self::Duplicate => write!(f, "instance already registered or nullifier already used"),
            Self::Conflict(detail) => write!(f, "state conflict: {detail}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error.to_string())
    }
}

/// Test-only crash injection points for the E1 atomic commit path. These are
/// *not* request parameters of the JSON Lines service; they are set directly
/// on an in-process [`crate::e1::E1Coordinator`] by integration tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    /// Fail after the CAS UPDATE but before `tx.commit()`; the whole SQLite
    /// transaction must roll back (no state advance, no nullifier, no op row).
    BeforeCommit,
    /// Fail immediately after `tx.commit()` succeeds; all rows are durable and
    /// must be recoverable byte-for-byte via `get_operation`.
    AfterCommit,
}

/// Inputs of one E1 operation written atomically with the state transition.
pub struct E1OperationParams<'a> {
    pub operation_id: &'a str,
    pub budget_id: &'a Fp,
    pub period_id: &'a Fp,
    pub binding_digest: &'a str,
    pub metering_quote_digest: &'a str,
}

/// The signed receipt returned by the e1.rs builder closure. `receipt_blob` is
/// the canonical serialized bytes of the *complete* E1TransitionReceipt.
pub struct E1BuiltReceipt {
    pub transition_digest: String,
    pub receipt_blob: Vec<u8>,
}

/// Result of the E1 atomic commit: either a fresh commit or an idempotent hit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum E1CommitOutcome {
    Committed {
        version: u64,
        transition_digest: String,
        receipt_blob: Vec<u8>,
    },
    Idempotent {
        transition_digest: String,
        receipt_blob: Vec<u8>,
    },
}

/// A persisted E1 operation row read back for idempotent recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct E1OperationRow {
    pub operation_id: String,
    pub budget_id: String,
    pub period_id: String,
    pub binding_digest: String,
    pub metering_quote_digest: String,
    pub transition_digest: String,
    pub nullifier: String,
    pub committed_version: u64,
    pub new_commitment: String,
    pub receipt_blob: Vec<u8>,
}

/// Persisted registration row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredInstance {
    pub budget_id: Fp,
    pub period_id: Fp,
    pub quota: Fp,
    pub policy: Fp,
    pub current_commitment: Fp,
    pub current_version: u64,
    pub authorization_bytes: Vec<u8>,
}

fn field_column(row: &rusqlite::Row<'_>, index: usize, name: &str) -> Result<Fp, rusqlite::Error> {
    let text: String = row.get(index)?;
    fp_from_hex(&text)
        .ok_or_else(|| rusqlite::Error::InvalidColumnType(index, name.to_owned(), Type::Text))
}

fn load_instance(
    conn: &Connection,
    budget_id: &Fp,
    period_id: &Fp,
) -> Result<Option<RegisteredInstance>, StoreError> {
    conn.query_row(
        "SELECT budget_id, period_id, quota, policy, current_commitment, \
                current_version, registration_authorization \
         FROM budget_instances WHERE budget_id = ?1 AND period_id = ?2",
        params![fp_to_hex(budget_id), fp_to_hex(period_id)],
        |row| {
            let version: i64 = row.get(5)?;
            Ok(RegisteredInstance {
                budget_id: field_column(row, 0, "budget_id")?,
                period_id: field_column(row, 1, "period_id")?,
                quota: field_column(row, 2, "quota")?,
                policy: field_column(row, 3, "policy")?,
                current_commitment: field_column(row, 4, "current_commitment")?,
                current_version: u64::try_from(version).map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        5,
                        "current_version".to_owned(),
                        Type::Integer,
                    )
                })?,
                authorization_bytes: row.get(6)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

fn nullifier_used(
    conn: &Connection,
    budget_id: &Fp,
    period_id: &Fp,
    nullifier: &Fp,
) -> Result<bool, StoreError> {
    conn.query_row(
        "SELECT 1 FROM used_nullifiers \
         WHERE budget_id = ?1 AND period_id = ?2 AND nullifier = ?3",
        params![
            fp_to_hex(budget_id),
            fp_to_hex(period_id),
            fp_to_hex(nullifier)
        ],
        |_| Ok(()),
    )
    .optional()
    .map(|entry| entry.is_some())
    .map_err(StoreError::from)
}

fn load_operation(
    conn: &Connection,
    operation_id: &str,
) -> Result<Option<E1OperationRow>, StoreError> {
    conn.query_row(
        "SELECT operation_id, budget_id, period_id, binding_digest, \
                metering_quote_digest, transition_digest, nullifier, \
                committed_version, new_commitment, receipt_blob \
         FROM budget_operations WHERE operation_id = ?1",
        params![operation_id],
        |row| {
            let version: i64 = row.get(7)?;
            Ok(E1OperationRow {
                operation_id: row.get(0)?,
                budget_id: row.get(1)?,
                period_id: row.get(2)?,
                binding_digest: row.get(3)?,
                metering_quote_digest: row.get(4)?,
                transition_digest: row.get(5)?,
                nullifier: row.get(6)?,
                committed_version: u64::try_from(version).map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        7,
                        "committed_version".to_owned(),
                        Type::Integer,
                    )
                })?,
                new_commitment: row.get(8)?,
                receipt_blob: row.get(9)?,
            })
        },
    )
    .optional()
    .map_err(StoreError::from)
}

/// A freshly opened connection. Each Coordinator call opens its own
/// connection, so concurrent callers really contend on SQLite locks.
pub struct StateStore {
    conn: Connection,
}

impl StateStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS budget_instances (
                 budget_id TEXT NOT NULL,
                 period_id TEXT NOT NULL,
                 quota TEXT NOT NULL,
                 policy TEXT NOT NULL,
                 current_commitment TEXT NOT NULL,
                 current_version INTEGER NOT NULL,
                 registration_authorization BLOB NOT NULL,
                 PRIMARY KEY (budget_id, period_id)
             );
             CREATE TABLE IF NOT EXISTS used_nullifiers (
                 budget_id TEXT NOT NULL,
                 period_id TEXT NOT NULL,
                 nullifier TEXT NOT NULL,
                 committed_version INTEGER NOT NULL,
                 UNIQUE (budget_id, period_id, nullifier)
             );
             CREATE TABLE IF NOT EXISTS cross_layer_scopes (
                 global_budget_id TEXT NOT NULL,
                 lease_id TEXT NOT NULL,
                 period_id TEXT NOT NULL,
                 budget_id TEXT NOT NULL,
                 binding_record_digest TEXT NOT NULL,
                 online_lease_grant_digest TEXT NOT NULL,
                 metering_policy_digest TEXT NOT NULL,
                 registration_authorization_digest TEXT NOT NULL,
                 UNIQUE (global_budget_id, lease_id, period_id)
             );
             CREATE TABLE IF NOT EXISTS budget_operations (
                 operation_id TEXT PRIMARY KEY,
                 budget_id TEXT NOT NULL,
                 period_id TEXT NOT NULL,
                 binding_digest TEXT NOT NULL,
                 metering_quote_digest TEXT NOT NULL,
                 transition_digest TEXT NOT NULL,
                 nullifier TEXT NOT NULL,
                 committed_version INTEGER NOT NULL,
                 new_commitment TEXT NOT NULL,
                 receipt_blob BLOB NOT NULL
             );",
        )?;
        Ok(Self { conn })
    }

    pub fn get_instance(
        &self,
        budget_id: &Fp,
        period_id: &Fp,
    ) -> Result<Option<RegisteredInstance>, StoreError> {
        load_instance(&self.conn, budget_id, period_id)
    }

    /// Register a unique initial state. Returns `Duplicate` when the key is
    /// already present, without modifying the stored row.
    pub fn register(
        &mut self,
        fields: &RegistrationFields,
        authorization_bytes: &[u8],
    ) -> Result<(), StoreError> {
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO budget_instances (
                 budget_id, period_id, quota, policy, current_commitment,
                 current_version, registration_authorization
             ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![
                fp_to_hex(&fields.budget_id),
                fp_to_hex(&fields.period_id),
                fp_to_hex(&fields.quota),
                fp_to_hex(&fields.policy),
                fp_to_hex(&fields.initial_commitment),
                authorization_bytes,
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::Duplicate);
        }
        Ok(())
    }

    pub fn is_nullifier_used(
        &self,
        budget_id: &Fp,
        period_id: &Fp,
        nullifier: &Fp,
    ) -> Result<bool, StoreError> {
        nullifier_used(&self.conn, budget_id, period_id, nullifier)
    }

    /// Insert a nullifier without advancing state. Only used by replay tests
    /// to isolate the "N already used" check; the Coordinator never calls it.
    pub fn insert_nullifier_raw(
        &mut self,
        budget_id: &Fp,
        period_id: &Fp,
        nullifier: &Fp,
        version: u64,
    ) -> Result<(), StoreError> {
        let changed = self.conn.execute(
            "INSERT OR IGNORE INTO used_nullifiers (
                 budget_id, period_id, nullifier, committed_version
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                fp_to_hex(budget_id),
                fp_to_hex(period_id),
                fp_to_hex(nullifier),
                i64::try_from(version).map_err(|_| StoreError::Encoding(
                    "version exceeds SQLite INTEGER".to_owned()
                ))?,
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::Duplicate);
        }
        Ok(())
    }

    pub fn used_nullifier_count(
        &self,
        budget_id: &Fp,
        period_id: &Fp,
    ) -> Result<usize, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM used_nullifiers WHERE budget_id = ?1 AND period_id = ?2",
            params![fp_to_hex(budget_id), fp_to_hex(period_id)],
            |row| row.get(0),
        )?;
        usize::try_from(count).map_err(|_| StoreError::Encoding("negative count".to_owned()))
    }

    /// Register an Issuer-signed cross-layer scope in the same transaction as
    /// the D11 budget instance. The `(global_budget_id, lease_id, period_id)`
    /// UNIQUE constraint is enforced by SQLite, not by the Python caller.
    ///
    /// Returns `Duplicate` for a byte-identical repeat and `Conflict` when the
    /// same scope key maps to a different budget_id or binding digest.
    pub fn register_cross_layer_scope(
        &mut self,
        fields: &RegistrationFields,
        authorization_bytes: &[u8],
        scope: &crate::e1::CrossLayerScopeFields,
        binding_record_digest: &str,
    ) -> Result<(), StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Same scope key -> either identical (Duplicate) or a conflict.
        if let Some(existing) = tx
            .query_row(
                "SELECT budget_id FROM cross_layer_scopes \
             WHERE global_budget_id = ?1 AND lease_id = ?2 AND period_id = ?3",
                params![scope.global_budget_id, scope.lease_id, scope.period_id_hex,],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(StoreError::from)?
        {
            if existing == scope.budget_id_hex {
                return Err(StoreError::Duplicate);
            }
            return Err(StoreError::Conflict(
                "scope key maps to a different budget_id".to_owned(),
            ));
        }
        // Register the D11 instance (only if absent) and the scope atomically.
        let changed = tx.execute(
            "INSERT OR IGNORE INTO budget_instances (
                 budget_id, period_id, quota, policy, current_commitment,
                 current_version, registration_authorization
             ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
            params![
                fp_to_hex(&fields.budget_id),
                fp_to_hex(&fields.period_id),
                fp_to_hex(&fields.quota),
                fp_to_hex(&fields.policy),
                fp_to_hex(&fields.initial_commitment),
                authorization_bytes,
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::Conflict(
                "budget instance already registered with different data".to_owned(),
            ));
        }
        tx.execute(
            "INSERT INTO cross_layer_scopes (
                 global_budget_id, lease_id, period_id, budget_id,
                 binding_record_digest, online_lease_grant_digest,
                 metering_policy_digest, registration_authorization_digest
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                scope.global_budget_id,
                scope.lease_id,
                scope.period_id_hex,
                scope.budget_id_hex,
                binding_record_digest,
                scope.online_lease_grant_digest,
                scope.metering_policy_digest,
                scope.registration_authorization_digest,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Look up an Issuer-signed cross-layer scope by its D11 instance key.
    pub fn get_cross_layer_scope(
        &self,
        budget_id: &Fp,
        period_id: &Fp,
    ) -> Result<Option<crate::e1::CrossLayerScopeFields>, StoreError> {
        self.conn
            .query_row(
                "SELECT global_budget_id, lease_id, period_id, budget_id,
                        online_lease_grant_digest, metering_policy_digest,
                        registration_authorization_digest
                 FROM cross_layer_scopes WHERE budget_id = ?1 AND period_id = ?2",
                params![fp_to_hex(budget_id), fp_to_hex(period_id)],
                |row| {
                    Ok(crate::e1::CrossLayerScopeFields {
                        global_budget_id: row.get(0)?,
                        lease_id: row.get(1)?,
                        period_id_hex: row.get(2)?,
                        budget_id_hex: row.get(3)?,
                        online_lease_grant_digest: row.get(4)?,
                        metering_policy_digest: row.get(5)?,
                        registration_authorization_digest: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Read a persisted E1 operation row (for idempotent recovery).
    pub fn get_operation_row(
        &self,
        operation_id: &str,
    ) -> Result<Option<E1OperationRow>, StoreError> {
        load_operation(&self.conn, operation_id)
    }

    /// E1 atomic transition: re-check state + nullifier, CAS-advance, build and
    /// sign the E1TransitionReceipt *inside* the transaction, insert the full
    /// operation row (including receipt_blob), then commit. Any failure (or an
    /// injected crash before commit) rolls the entire transaction back.
    ///
    /// `build_receipt` is called with the final `next_version` so the receipt's
    /// unsigned_payload can include CAS-produced fields (state_version,
    /// new_commitment, nullifier) before signing. This is the closure supplied
    /// by `e1.rs`; `state_store` stays ignorant of receipt field semantics.
    pub fn cas_commit_e1<F>(
        &mut self,
        op: &E1OperationParams<'_>,
        c_old: &Fp,
        c_new: &Fp,
        nullifier: &Fp,
        crash: Option<CrashPoint>,
        build_receipt: F,
    ) -> Result<E1CommitOutcome, StoreError>
    where
        F: FnOnce(u64, &Fp, &Fp) -> Result<E1BuiltReceipt, StoreError>,
    {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        // Idempotency: same operation_id with identical binding/quote digests
        // returns the stored receipt without re-consuming state.
        if let Some(existing) = load_operation(&tx, op.operation_id)? {
            // Full digest match AND identical state artifacts (E1.0 §6.3):
            // a different C_new/N with the same operation_id must NOT reuse
            // the stored receipt — that would be a different transition.
            if existing.binding_digest == op.binding_digest
                && existing.metering_quote_digest == op.metering_quote_digest
                && existing.budget_id == fp_to_hex(op.budget_id)
                && existing.period_id == fp_to_hex(op.period_id)
                && existing.new_commitment == fp_to_hex(c_new)
                && existing.nullifier == fp_to_hex(nullifier)
            {
                return Ok(E1CommitOutcome::Idempotent {
                    transition_digest: existing.transition_digest,
                    receipt_blob: existing.receipt_blob,
                });
            }
            return Err(StoreError::Conflict(
                "operation_id reused with different digests or state artifacts".to_owned(),
            ));
        }

        let current = load_instance(&tx, op.budget_id, op.period_id)?
            .ok_or_else(|| StoreError::Conflict("instance disappeared".to_owned()))?;
        if current.current_commitment != *c_old {
            return Err(StoreError::Conflict(
                "C_old is not the current commitment".to_owned(),
            ));
        }
        if nullifier_used(&tx, op.budget_id, op.period_id, nullifier)? {
            return Err(StoreError::Conflict("nullifier already used".to_owned()));
        }
        let next_version = current
            .current_version
            .checked_add(1)
            .ok_or_else(|| StoreError::Encoding("version overflow".to_owned()))?;
        let next_version_i64 = i64::try_from(next_version)
            .map_err(|_| StoreError::Encoding("version exceeds SQLite INTEGER".to_owned()))?;

        tx.execute(
            "INSERT INTO used_nullifiers (
                 budget_id, period_id, nullifier, committed_version
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                fp_to_hex(op.budget_id),
                fp_to_hex(op.period_id),
                fp_to_hex(nullifier),
                next_version_i64,
            ],
        )?;
        let changed = tx.execute(
            "UPDATE budget_instances
             SET current_commitment = ?1, current_version = ?2
             WHERE budget_id = ?3 AND period_id = ?4 AND current_commitment = ?5",
            params![
                fp_to_hex(c_new),
                next_version_i64,
                fp_to_hex(op.budget_id),
                fp_to_hex(op.period_id),
                fp_to_hex(c_old),
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict("state pointer CAS failed".to_owned()));
        }

        // Crash BEFORE commit: drop tx -> full rollback (no state, no N, no op).
        if crash == Some(CrashPoint::BeforeCommit) {
            return Err(StoreError::Conflict(
                "injected crash before commit".to_owned(),
            ));
        }

        // Build + sign the receipt using CAS-produced final values, still inside
        // the transaction. Nothing here is a caller-supplied "verified" flag.
        let built = build_receipt(next_version, c_new, nullifier)?;
        tx.execute(
            "INSERT INTO budget_operations (
                 operation_id, budget_id, period_id, binding_digest,
                 metering_quote_digest, transition_digest, nullifier,
                 committed_version, new_commitment, receipt_blob
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                op.operation_id,
                fp_to_hex(op.budget_id),
                fp_to_hex(op.period_id),
                op.binding_digest,
                op.metering_quote_digest,
                built.transition_digest,
                fp_to_hex(nullifier),
                next_version_i64,
                fp_to_hex(c_new),
                built.receipt_blob,
            ],
        )?;
        tx.commit()?;

        // Crash AFTER commit: all rows are durable; recoverable via get_operation.
        if crash == Some(CrashPoint::AfterCommit) {
            return Err(StoreError::Conflict(
                "injected crash after commit".to_owned(),
            ));
        }

        Ok(E1CommitOutcome::Committed {
            version: next_version,
            transition_digest: built.transition_digest,
            receipt_blob: built.receipt_blob,
        })
    }

    /// Atomic CAS. The signature takes only public field values: the caller
    /// (Coordinator) has already verified the proof before entering this
    /// function. All state/nullifier checks below are repeated inside the
    /// `BEGIN IMMEDIATE` transaction.
    pub fn cas_commit(
        &mut self,
        budget_id: &Fp,
        period_id: &Fp,
        c_old: &Fp,
        c_new: &Fp,
        nullifier: &Fp,
    ) -> Result<u64, StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_instance(&tx, budget_id, period_id)?
            .ok_or_else(|| StoreError::Conflict("instance disappeared".to_owned()))?;
        if current.current_commitment != *c_old {
            return Err(StoreError::Conflict(
                "C_old is not the current commitment".to_owned(),
            ));
        }
        if nullifier_used(&tx, budget_id, period_id, nullifier)? {
            return Err(StoreError::Conflict("nullifier already used".to_owned()));
        }
        let next_version = current
            .current_version
            .checked_add(1)
            .ok_or_else(|| StoreError::Encoding("version overflow".to_owned()))?;
        let next_version_i64 = i64::try_from(next_version)
            .map_err(|_| StoreError::Encoding("version exceeds SQLite INTEGER".to_owned()))?;
        tx.execute(
            "INSERT INTO used_nullifiers (
                 budget_id, period_id, nullifier, committed_version
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                fp_to_hex(budget_id),
                fp_to_hex(period_id),
                fp_to_hex(nullifier),
                next_version_i64,
            ],
        )?;
        let changed = tx.execute(
            "UPDATE budget_instances
             SET current_commitment = ?1, current_version = ?2
             WHERE budget_id = ?3 AND period_id = ?4 AND current_commitment = ?5",
            params![
                fp_to_hex(c_new),
                next_version_i64,
                fp_to_hex(budget_id),
                fp_to_hex(period_id),
                fp_to_hex(c_old),
            ],
        )?;
        if changed != 1 {
            // Dropping `tx` rolls back the nullifier insert as well.
            return Err(StoreError::Conflict("state pointer CAS failed".to_owned()));
        }
        tx.commit()?;
        Ok(next_version)
    }

    /// Test-only DB check used by the registration-integrity path.
    pub fn authorization_matches_row(
        &self,
        row: &RegisteredInstance,
        reencoded: &[u8],
    ) -> Result<bool, StoreError> {
        let stored: Vec<u8> = self.conn.query_row(
            "SELECT registration_authorization FROM budget_instances
             WHERE budget_id = ?1 AND period_id = ?2",
            params![fp_to_hex(&row.budget_id), fp_to_hex(&row.period_id)],
            |row| row.get(0),
        )?;
        Ok(stored == reencoded)
    }

    /// Ensure a registered quota is inside the range enforced by the circuit.
    pub fn validate_stored_quota(row: &RegisteredInstance) -> Result<(), CoordinatorError> {
        let quota = crate::fp_to_u64_checked(&row.quota).ok_or_else(|| {
            CoordinatorError::InvalidPublicInput("stored quota does not fit uint32".to_owned())
        })?;
        if quota == 0 || quota > MAX_UINT32 {
            return Err(CoordinatorError::InvalidPublicInput(
                "stored quota is outside uint32".to_owned(),
            ));
        }
        Ok(())
    }
}
