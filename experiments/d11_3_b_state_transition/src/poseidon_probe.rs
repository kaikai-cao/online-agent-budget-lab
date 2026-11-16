//! Poseidon compatibility probe for D11.3-B.0.
//!
//! Frozen instance: `P128Pow5T3` over Pallas base field (`halo2_proofs::pasta::Fp`),
//! width T = 3, rate R = 2, S-box x^5, `ConstantLength<L>` domain.
//!
//! The native hash uses `halo2_gadgets::poseidon::primitives` (re-exported
//! `halo2_poseidon` 0.2.0); the in-circuit hash uses the same spec through the
//! official `Pow5Chip`. We deliberately do **not** reimplement the permutation.

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};

/// Poseidon state width (T). `P128Pow5T3` is defined for (T, RATE) = (3, 2).
pub const WIDTH: usize = 3;
/// Poseidon sponge rate (R).
pub const RATE: usize = 2;
/// `Params::new(k)` used by every probe circuit. 2^10 rows comfortably fit the
/// five permutations needed by a 7-word fixed-length hash (64 rounds each).
pub const K_PROBE: u32 = 10;

/// Native (host-side) Poseidon hash with the frozen instance.
///
/// This is the reference value that the circuit must reproduce exactly.
pub fn native_poseidon<const L: usize>(message: [Fp; L]) -> Fp {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init().hash(message)
}

/// Configuration for [`PoseidonHashCircuit`].
#[derive(Clone, Debug)]
pub struct PoseidonProbeConfig {
    /// The official `Pow5Chip` configuration.
    pub poseidon: Pow5Config<Fp, WIDTH, RATE>,
    /// Advice column holding the L input words, one per row.
    message: Column<Advice>,
    /// Single instance column: row 0 = expected Poseidon output.
    instance: Column<Instance>,
}

/// Minimal circuit that computes `Poseidon_L(message)` and binds the result to
/// `instance[0]`.
///
/// Binding the output to a public instance cell (rather than to a private
/// witness) is what makes the equality test meaningful: a wrong expected value
/// must make `MockProver`/`verify_proof` fail.
#[derive(Clone, Debug)]
pub struct PoseidonHashCircuit<const L: usize> {
    /// The L message words, already encoded as `Fp` (including the leading
    /// domain separator for the D11.3-A commitments).
    pub message: [Fp; L],
}

impl<const L: usize> Circuit<Fp> for PoseidonHashCircuit<L> {
    type Config = PoseidonProbeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: [Fp::ZERO; L],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // Columns required by Pow5Chip, configured exactly as in the upstream
        // halo2_gadgets 0.6.0 tests (no custom Poseidon gates).
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        // Needed by `assign_advice_from_constant` in the chip's initial_state.
        meta.enable_constant(rc_b[0]);

        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state.try_into().expect("state width"),
            partial_sbox,
            rc_a.try_into().expect("rc_a width"),
            rc_b.try_into().expect("rc_b width"),
        );

        // The message cells are copy-constrained into the chip's state columns
        // by `add_input`, so the source column must be equality-enabled.
        let message = meta.advice_column();
        meta.enable_equality(message);

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        PoseidonProbeConfig {
            poseidon,
            message,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Assign the L input words into a dedicated advice column. This works
        // for L > RATE too: the sponge's `absorb` handles chunking internally.
        let message = layouter.assign_region(
            || "load message",
            |mut region| {
                (0..L)
                    .map(|i| {
                        region.assign_advice(
                            || format!("message[{i}]"),
                            config.message,
                            i,
                            || Value::known(self.message[i]),
                        )
                    })
                    .collect::<Result<Vec<AssignedCell<Fp, Fp>>, Error>>()
            },
        )?;

        let chip = Pow5Chip::construct(config.poseidon.clone());
        let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(
            layouter.namespace(|| "hash"),
            message.try_into().expect("message length"),
        )?;

        // Public binding: instance[0] must equal the circuit-computed hash.
        layouter.constrain_instance(output.cell(), config.instance, 0)?;

        Ok(())
    }
}
