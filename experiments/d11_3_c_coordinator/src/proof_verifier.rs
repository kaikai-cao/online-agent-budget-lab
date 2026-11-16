//! Real Halo2 proof verification for D11.3-C, reusing the frozen B.1 circuit.
//!
//! No `MockProver` is used here, and callers cannot pass a `verified` flag:
//! [`ProofVerifier::verify_proof`] is the only acceptance path and always runs
//! `plonk::verify_proof` over the eight public instance rows.

use std::sync::{Arc, OnceLock};

use d11_3_b_state_transition::{
    state_transition::StateTransitionCircuit, StateWitness, INSTANCE_ROWS,
};
use halo2_proofs::{
    arithmetic::Field,
    pasta::{EqAffine, Fp},
    plonk::{self, ProvingKey, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};

/// The B.1 circuit size, measured empirically in B.1 (`k = 9` fails with
/// `NotEnoughRowsAvailable`; `k = 10` verifies).
pub const K: u32 = 10;

/// Experimental key material for this prototype.
///
/// **Not a production key-management scheme.** Params, proving key and
/// verifying key are generated once per process and held in memory. A real
/// deployment needs an audited setup, key distribution and rotation story.
pub struct ExperimentalProofAssets {
    pub params: Arc<Params<EqAffine>>,
    pub proving_key: Arc<ProvingKey<EqAffine>>,
    pub verifying_key: Arc<VerifyingKey<EqAffine>>,
}

fn keygen_circuit() -> StateTransitionCircuit {
    // Shape only; keygen does not need a satisfying assignment.
    StateTransitionCircuit::new(StateWitness {
        budget_id: Fp::ZERO,
        period_id: Fp::ZERO,
        quota: 1,
        cost: 1,
        u_old: 0,
        u_new: 1,
        slack: 0,
        r_old: Fp::ZERO,
        r_new: Fp::ZERO,
        nf_secret: Fp::ZERO,
        policy: Fp::ZERO,
    })
}

/// Process-wide experimental setup, generated at most once.
pub fn experimental_proof_assets() -> &'static ExperimentalProofAssets {
    static ASSETS: OnceLock<ExperimentalProofAssets> = OnceLock::new();
    ASSETS.get_or_init(|| {
        let circuit = keygen_circuit();
        let params = Arc::new(Params::<EqAffine>::new(K));
        let vk = plonk::keygen_vk(params.as_ref(), &circuit).expect("experimental keygen_vk");
        let pk = plonk::keygen_pk(params.as_ref(), vk, &circuit).expect("experimental keygen_pk");
        ExperimentalProofAssets {
            params,
            verifying_key: Arc::new(pk.get_vk().clone()),
            proving_key: Arc::new(pk),
        }
    })
}

/// Create a real proof for a witness. This is a prototype/test helper for the
/// prover side; the Coordinator never calls it and never trusts caller-supplied
/// "verified" flags.
pub fn prove_experimental(witness: &StateWitness) -> (Vec<u8>, [Fp; INSTANCE_ROWS]) {
    let assets = experimental_proof_assets();
    let circuit = StateTransitionCircuit::new(witness.clone());
    let instance = witness.public_inputs();
    let instances: Vec<&[Fp]> = vec![instance.as_slice()];
    let instance_refs: Vec<&[&[Fp]]> = vec![&instances];
    let mut transcript = Blake2bWrite::<_, EqAffine, _>::init(vec![]);
    plonk::create_proof(
        assets.params.as_ref(),
        assets.proving_key.as_ref(),
        &[circuit],
        &instance_refs,
        &mut UnwrapErr(SysRng),
        &mut transcript,
    )
    .expect("experimental create_proof");
    (transcript.finalize(), instance)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofVerifyError {
    /// Halo2 rejected the proof for the supplied instance.
    InvalidProof(String),
}

impl std::fmt::Display for ProofVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProof(detail) => write!(f, "invalid Halo2 proof: {detail}"),
        }
    }
}

impl std::error::Error for ProofVerifyError {}

/// Verifier held by the Coordinator. Uses the B.1 k=10 parameters and VK.
#[derive(Clone)]
pub struct ProofVerifier {
    params: Arc<Params<EqAffine>>,
    verifying_key: Arc<VerifyingKey<EqAffine>>,
}

impl ProofVerifier {
    /// Build from the process-wide experimental setup.
    pub fn new_experimental() -> Self {
        let assets = experimental_proof_assets();
        Self {
            params: Arc::clone(&assets.params),
            verifying_key: Arc::clone(&assets.verifying_key),
        }
    }

    /// Verify a proof against the full eight-row public instance.
    pub fn verify_proof(
        &self,
        proof: &[u8],
        instance: &[Fp; INSTANCE_ROWS],
    ) -> Result<(), ProofVerifyError> {
        let instances: Vec<&[Fp]> = vec![instance.as_slice()];
        let instance_refs: Vec<&[&[Fp]]> = vec![&instances];
        let strategy = SingleVerifier::new(self.params.as_ref());
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
        plonk::verify_proof(
            self.params.as_ref(),
            self.verifying_key.as_ref(),
            strategy,
            &instance_refs,
            &mut transcript,
        )
        .map_err(|error| ProofVerifyError::InvalidProof(format!("{error:?}")))
    }
}
