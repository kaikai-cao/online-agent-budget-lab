//! Issuer-signed initial state registration (D11.3-A §4, §7.1).
//!
//! The authorization binds exactly `(budget_id, period_id, Q, P, C_0)` under a
//! fixed domain separator and the canonical 32-byte field encoding from the
//! crate root. It is a signature over public fields only: it does **not** prove
//! that the Prover knows the opening `(u_0 = 0, r_0, K_0)` of `C_0`. That
//! limitation is intentional and is part of the frozen D11.3-A protocol.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use halo2_proofs::pasta::Fp;

use crate::{fp_from_bytes, fp_to_bytes, fp_to_u64_checked, FIELD_BYTES, MAX_UINT32};

/// Domain prefix for the registration signature message. Changing it
/// invalidates every previously issued authorization.
pub const REGISTRATION_DOMAIN: &[u8] = b"D11.3-C-REGISTRATION-v1";
/// Number of signed field elements: budget_id, period_id, Q, P, C_0.
pub const FIELD_COUNT: usize = 5;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;
/// Encoded authorization length: domain || 5 × 32-byte fields || signature.
pub const ENCODED_LEN: usize =
    REGISTRATION_DOMAIN.len() + FIELD_COUNT * FIELD_BYTES + SIGNATURE_LEN;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationError {
    /// Byte string is not a well-formed encoded authorization.
    InvalidEncoding(String),
    /// Signature does not verify under the coordinator's issuer key.
    InvalidSignature,
    /// Registered quota is zero, larger than uint32, or otherwise invalid.
    InvalidQuota(String),
}

impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEncoding(detail) => write!(f, "invalid registration encoding: {detail}"),
            Self::InvalidSignature => write!(f, "issuer registration signature is invalid"),
            Self::InvalidQuota(detail) => write!(f, "invalid registration quota: {detail}"),
        }
    }
}

impl std::error::Error for RegistrationError {}

/// The five fields bound by an issuer registration authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationFields {
    pub budget_id: Fp,
    pub period_id: Fp,
    pub quota: Fp,
    pub policy: Fp,
    pub initial_commitment: Fp,
}

impl RegistrationFields {
    /// Deterministic signature message: fixed prefix followed by five
    /// canonical 32-byte little-endian field representations.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REGISTRATION_DOMAIN.len() + FIELD_COUNT * FIELD_BYTES);
        out.extend_from_slice(REGISTRATION_DOMAIN);
        for field in [
            &self.budget_id,
            &self.period_id,
            &self.quota,
            &self.policy,
            &self.initial_commitment,
        ] {
            out.extend_from_slice(&fp_to_bytes(field));
        }
        out
    }

    /// Check protocol-level field validity. `Q >= 1` and `Q <= 2^32-1` are
    /// required by D11.3-A §4.2 and by the B.1 range constraints.
    pub fn validate(&self) -> Result<(), RegistrationError> {
        let Some(quota) = fp_to_u64_checked(&self.quota) else {
            return Err(RegistrationError::InvalidQuota(
                "quota does not fit uint32".to_owned(),
            ));
        };
        if quota == 0 || quota > MAX_UINT32 {
            return Err(RegistrationError::InvalidQuota(
                "quota must satisfy 1 <= Q <= 2^32-1".to_owned(),
            ));
        }
        Ok(())
    }

    fn from_message(message: &[u8]) -> Result<Self, RegistrationError> {
        if message.len() != REGISTRATION_DOMAIN.len() + FIELD_COUNT * FIELD_BYTES {
            return Err(RegistrationError::InvalidEncoding(
                "unexpected signed-message length".to_owned(),
            ));
        }
        if &message[..REGISTRATION_DOMAIN.len()] != REGISTRATION_DOMAIN {
            return Err(RegistrationError::InvalidEncoding(
                "unexpected domain separator".to_owned(),
            ));
        }
        let mut fields = [[0u8; FIELD_BYTES]; FIELD_COUNT];
        for (index, slot) in fields.iter_mut().enumerate() {
            let start = REGISTRATION_DOMAIN.len() + index * FIELD_BYTES;
            slot.copy_from_slice(&message[start..start + FIELD_BYTES]);
        }
        let decoded = fields
            .iter()
            .map(fp_from_bytes)
            .collect::<Option<Vec<Fp>>>()
            .ok_or_else(|| {
                RegistrationError::InvalidEncoding("non-canonical field element".to_owned())
            })?;
        Ok(Self {
            budget_id: decoded[0],
            period_id: decoded[1],
            quota: decoded[2],
            policy: decoded[3],
            initial_commitment: decoded[4],
        })
    }
}

/// A complete, self-contained registration authorization record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationAuthorization {
    pub fields: RegistrationFields,
    pub issuer_signature: [u8; SIGNATURE_LEN],
}

impl RegistrationAuthorization {
    /// Stable serialization used both for persistence and for signature input.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.fields.encode();
        out.extend_from_slice(&self.issuer_signature);
        out
    }

    /// Parse a stored authorization record. Field validity is enforced here,
    /// but the issuer signature must still be checked separately.
    pub fn decode(bytes: &[u8]) -> Result<Self, RegistrationError> {
        if bytes.len() != ENCODED_LEN {
            return Err(RegistrationError::InvalidEncoding(format!(
                "expected {ENCODED_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let split = ENCODED_LEN - SIGNATURE_LEN;
        let fields = RegistrationFields::from_message(&bytes[..split])?;
        fields.validate()?;
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[split..]);
        Ok(Self {
            fields,
            issuer_signature: signature,
        })
    }

    pub fn verify(&self, issuer: &VerifyingKey) -> Result<(), RegistrationError> {
        self.fields.validate()?;
        let signature = Signature::from_bytes(&self.issuer_signature);
        issuer
            .verify_strict(&self.fields.encode(), &signature)
            .map_err(|_| RegistrationError::InvalidSignature)
    }
}

/// Issue a registration authorization. This helper is for the Issuer side of
/// the experiment; the Coordinator only ever calls [`RegistrationAuthorization::verify`].
pub fn sign_registration(
    fields: &RegistrationFields,
    issuer: &SigningKey,
) -> Result<RegistrationAuthorization, RegistrationError> {
    fields.validate()?;
    let signature = issuer.sign(&fields.encode());
    Ok(RegistrationAuthorization {
        fields: fields.clone(),
        issuer_signature: signature.to_bytes(),
    })
}
