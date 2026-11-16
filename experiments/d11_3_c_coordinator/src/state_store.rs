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
                i64::try_from(version).unwrap_or(i64::MAX),
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
        tx.execute(
            "INSERT INTO used_nullifiers (
                 budget_id, period_id, nullifier, committed_version
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                fp_to_hex(budget_id),
                fp_to_hex(period_id),
                fp_to_hex(nullifier),
                i64::try_from(next_version).unwrap_or(i64::MAX),
            ],
        )?;
        let changed = tx.execute(
            "UPDATE budget_instances
             SET current_commitment = ?1, current_version = ?2
             WHERE budget_id = ?3 AND period_id = ?4 AND current_commitment = ?5",
            params![
                fp_to_hex(c_new),
                i64::try_from(next_version).unwrap_or(i64::MAX),
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
