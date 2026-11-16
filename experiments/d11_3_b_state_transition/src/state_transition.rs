//! D11.3-B.1 — complete private budget state-transition circuit.
//!
//! One circuit jointly enforces:
//!   1. Q, c, u_old, u_new, s are uint32; Q != 0 and c != 0.
//!   2. u_old + c - u_new = 0  and  u_new + s - Q = 0  (two independent gates).
//!   3. K = Poseidon_4(D_key, nf_secret, budget_id, period_id), computed by the
//!      Poseidon gadget (never supplied as a free witness).
//!   4. C_old = Poseidon_7(D_state, budget_id, period_id, Q, u_old, r_old, K).
//!   5. C_new = Poseidon_7(D_state, budget_id, period_id, Q, u_new, r_new, K),
//!      using the SAME circuit-computed K (enforced by an explicit gate).
//!   6. N = Poseidon_5(D_nf, nf_secret, budget_id, period_id, C_old).
//!
//! Public instance rows: [budget_id, period_id, Q, c, C_old, C_new, N, P].
//! P occupies row 7 but is deliberately NOT part of the circuit relation: the
//! Coordinator compares it with registered_policy[(budget_id, period_id)].

use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Instance, Selector},
    poly::Rotation,
};

use crate::{
    native_poseidon,
    poseidon_probe::{RATE, WIDTH},
    range::RangeConfig,
    D_KEY, D_NF, D_STATE,
};

/// Number of public input rows.
pub const INSTANCE_ROWS: usize = 8;

/// Complete witness of one transition. `policy` is public but unconstrained.
#[derive(Clone, Debug)]
pub struct StateWitness {
    pub budget_id: Fp,
    pub period_id: Fp,
    pub quota: u64,
    pub cost: u64,
    pub u_old: u64,
    pub u_new: u64,
    pub slack: u64,
    pub r_old: Fp,
    pub r_new: Fp,
    pub nf_secret: Fp,
    pub policy: Fp,
}

impl StateWitness {
    /// Compute K, C_old, C_new and N with the frozen native Poseidon instance.
    /// Used to build public inputs and deterministic test vectors.
    pub fn commitments(&self) -> (Fp, Fp, Fp, Fp) {
        let k = native_poseidon([
            Fp::from(D_KEY),
            self.nf_secret,
            self.budget_id,
            self.period_id,
        ]);
        let c_old = native_poseidon([
            Fp::from(D_STATE),
            self.budget_id,
            self.period_id,
            Fp::from(self.quota),
            Fp::from(self.u_old),
            self.r_old,
            k,
        ]);
        let c_new = native_poseidon([
            Fp::from(D_STATE),
            self.budget_id,
            self.period_id,
            Fp::from(self.quota),
            Fp::from(self.u_new),
            self.r_new,
            k,
        ]);
        let n = native_poseidon([
            Fp::from(D_NF),
            self.nf_secret,
            self.budget_id,
            self.period_id,
            c_old,
        ]);
        (k, c_old, c_new, n)
    }

    /// Public instance layout: [budget_id, period_id, Q, c, C_old, C_new, N, P].
    pub fn public_inputs(&self) -> [Fp; INSTANCE_ROWS] {
        let (_, c_old, c_new, n) = self.commitments();
        [
            self.budget_id,
            self.period_id,
            Fp::from(self.quota),
            Fp::from(self.cost),
            c_old,
            c_new,
            n,
            self.policy,
        ]
    }
}

#[derive(Clone, Debug)]
pub struct StateTransitionConfig {
    pub poseidon: Pow5Config<Fp, WIDTH, RATE>,
    pub range: RangeConfig,
    /// Cells copied into when enforcing the two budget equations.
    eq: Column<Advice>,
    q_eq_old_to_new: Selector,
    q_eq_new_to_quota: Selector,
    /// Copy of the gadget-computed K, and the K actually used by C_new.
    k_copy: Column<Advice>,
    k_new: Column<Advice>,
    q_same_k: Selector,
    /// Cells assigned from fixed constants (domain separators).
    constant: Column<Advice>,
    /// Miscellaneous private advice: ids, nf_secret, r_old, r_new.
    misc: Column<Advice>,
    instance: Column<Instance>,
}

#[derive(Clone, Debug)]
pub struct StateTransitionCircuit {
    pub witness: StateWitness,
    /// Negative-test only: force C_new to use a K different from the computed
    /// one. Honest proofs must leave this as `None`.
    pub k_new_override: Option<Fp>,
}

impl StateTransitionCircuit {
    pub fn new(witness: StateWitness) -> Self {
        Self {
            witness,
            k_new_override: None,
        }
    }
}

impl Circuit<Fp> for StateTransitionCircuit {
    type Config = StateTransitionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            witness: StateWitness {
                budget_id: Fp::ZERO,
                period_id: Fp::ZERO,
                quota: 0,
                cost: 0,
                u_old: 0,
                u_new: 0,
                slack: 0,
                r_old: Fp::ZERO,
                r_new: Fp::ZERO,
                nf_secret: Fp::ZERO,
                policy: Fp::ZERO,
            },
            k_new_override: None,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // --- official Poseidon chip columns (same setup as D11.3-B.0) ---
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state.try_into().expect("state width"),
            partial_sbox,
            rc_a.try_into().expect("rc_a width"),
            rc_b.try_into().expect("rc_b width"),
        );

        let range = RangeConfig::configure(meta);

        let eq = meta.advice_column();
        meta.enable_equality(eq);
        let k_copy = meta.advice_column();
        meta.enable_equality(k_copy);
        let k_new = meta.advice_column();
        meta.enable_equality(k_new);
        let constant = meta.advice_column();
        meta.enable_equality(constant);
        let misc = meta.advice_column();
        meta.enable_equality(misc);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let q_eq_old_to_new = meta.selector();
        let q_eq_new_to_quota = meta.selector();
        let q_same_k = meta.selector();

        // 6a: u_old + c - u_new = 0, with cells at rows 0, 1, 2.
        meta.create_gate("u_old + c - u_new", |meta| {
            let s = meta.query_selector(q_eq_old_to_new);
            let u_old = meta.query_advice(eq, Rotation::cur());
            let c = meta.query_advice(eq, Rotation::next());
            let u_new = meta.query_advice(eq, Rotation(2));
            Constraints::with_selector(s, [u_old + c - u_new])
        });

        // 6b: u_new + s - Q = 0, with cells at rows 0, 1, 2.
        meta.create_gate("u_new + s - Q", |meta| {
            let s = meta.query_selector(q_eq_new_to_quota);
            let u_new = meta.query_advice(eq, Rotation::cur());
            let slack = meta.query_advice(eq, Rotation::next());
            let quota = meta.query_advice(eq, Rotation(2));
            Constraints::with_selector(s, [u_new + slack - quota])
        });

        // Same K across old and new state: k_new - k_copy = 0.
        meta.create_gate("same K for both states", |meta| {
            let s = meta.query_selector(q_same_k);
            let k_new = meta.query_advice(k_new, Rotation::cur());
            let k_copy = meta.query_advice(k_copy, Rotation::cur());
            Constraints::with_selector(s, [k_new - k_copy])
        });

        StateTransitionConfig {
            poseidon,
            range,
            eq,
            q_eq_old_to_new,
            q_eq_new_to_quota,
            k_copy,
            k_new,
            q_same_k,
            constant,
            misc,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let w = &self.witness;

        // --- B1-1: five uint32 range constraints ---
        let quota_cell = layouter.assign_region(
            || "range Q",
            |mut region| config.range.assign_u32(&mut region, w.quota, true, "Q"),
        )?;
        let cost_cell = layouter.assign_region(
            || "range c",
            |mut region| config.range.assign_u32(&mut region, w.cost, true, "c"),
        )?;
        let u_old_cell = layouter.assign_region(
            || "range u_old",
            |mut region| {
                config
                    .range
                    .assign_u32(&mut region, w.u_old, false, "u_old")
            },
        )?;
        let u_new_cell = layouter.assign_region(
            || "range u_new",
            |mut region| {
                config
                    .range
                    .assign_u32(&mut region, w.u_new, false, "u_new")
            },
        )?;
        let slack_cell = layouter.assign_region(
            || "range s",
            |mut region| config.range.assign_u32(&mut region, w.slack, false, "s"),
        )?;

        // --- B1-2: two independent equations over the range-checked cells ---
        layouter.assign_region(
            || "equation 6a",
            |mut region| {
                config.q_eq_old_to_new.enable(&mut region, 0)?;
                u_old_cell.copy_advice(|| "6a u_old", &mut region, config.eq, 0)?;
                cost_cell.copy_advice(|| "6a c", &mut region, config.eq, 1)?;
                u_new_cell.copy_advice(|| "6a u_new", &mut region, config.eq, 2)?;
                Ok(())
            },
        )?;
        layouter.assign_region(
            || "equation 6b",
            |mut region| {
                config.q_eq_new_to_quota.enable(&mut region, 0)?;
                u_new_cell.copy_advice(|| "6b u_new", &mut region, config.eq, 0)?;
                slack_cell.copy_advice(|| "6b s", &mut region, config.eq, 1)?;
                quota_cell.copy_advice(|| "6b Q", &mut region, config.eq, 2)?;
                Ok(())
            },
        )?;

        // --- private ids/secrets and public id binding ---
        let budget_cell = layouter.assign_region(
            || "budget_id",
            |mut region| {
                region.assign_advice(|| "budget_id", config.misc, 0, || Value::known(w.budget_id))
            },
        )?;
        let period_cell = layouter.assign_region(
            || "period_id",
            |mut region| {
                region.assign_advice(|| "period_id", config.misc, 0, || Value::known(w.period_id))
            },
        )?;
        let nf_secret_cell = layouter.assign_region(
            || "nf_secret",
            |mut region| {
                region.assign_advice(|| "nf_secret", config.misc, 0, || Value::known(w.nf_secret))
            },
        )?;
        let r_old_cell = layouter.assign_region(
            || "r_old",
            |mut region| region.assign_advice(|| "r_old", config.misc, 0, || Value::known(w.r_old)),
        )?;
        let r_new_cell = layouter.assign_region(
            || "r_new",
            |mut region| region.assign_advice(|| "r_new", config.misc, 0, || Value::known(w.r_new)),
        )?;

        layouter.constrain_instance(budget_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(period_cell.cell(), config.instance, 1)?;
        layouter.constrain_instance(quota_cell.cell(), config.instance, 2)?;
        layouter.constrain_instance(cost_cell.cell(), config.instance, 3)?;

        // --- domain separators as constrained constants ---
        let d_key_cell = layouter.assign_region(
            || "D_KEY",
            |mut region| {
                region.assign_advice_from_constant(|| "D_KEY", config.constant, 0, Fp::from(D_KEY))
            },
        )?;
        let d_state_cell = layouter.assign_region(
            || "D_STATE",
            |mut region| {
                region.assign_advice_from_constant(
                    || "D_STATE",
                    config.constant,
                    0,
                    Fp::from(D_STATE),
                )
            },
        )?;
        let d_nf_cell = layouter.assign_region(
            || "D_NF",
            |mut region| {
                region.assign_advice_from_constant(|| "D_NF", config.constant, 0, Fp::from(D_NF))
            },
        )?;

        // --- B1-3: K derived inside the circuit, then reused by both states ---
        let k_cell = poseidon_hash(
            &config,
            &mut layouter,
            "K = Poseidon_4",
            [
                d_key_cell,
                nf_secret_cell.clone(),
                budget_cell.clone(),
                period_cell.clone(),
            ],
        )?;

        let (k_copy_cell, k_new_cell) = layouter.assign_region(
            || "same K",
            |mut region| {
                config.q_same_k.enable(&mut region, 0)?;
                let kc = k_cell.copy_advice(|| "K used by C_old", &mut region, config.k_copy, 0)?;
                let kn = region.assign_advice(
                    || "K used by C_new",
                    config.k_new,
                    0,
                    || match self.k_new_override {
                        Some(v) => Value::known(v),
                        None => k_cell.value().copied(),
                    },
                )?;
                Ok((kc, kn))
            },
        )?;

        let c_old_cell = poseidon_hash(
            &config,
            &mut layouter,
            "C_old = Poseidon_7",
            [
                d_state_cell.clone(),
                budget_cell.clone(),
                period_cell.clone(),
                quota_cell.clone(),
                u_old_cell,
                r_old_cell,
                k_copy_cell,
            ],
        )?;
        let c_new_cell = poseidon_hash(
            &config,
            &mut layouter,
            "C_new = Poseidon_7",
            [
                d_state_cell,
                budget_cell.clone(),
                period_cell.clone(),
                quota_cell,
                u_new_cell,
                r_new_cell,
                k_new_cell,
            ],
        )?;
        let nullifier_cell = poseidon_hash(
            &config,
            &mut layouter,
            "N = Poseidon_5",
            [
                d_nf_cell,
                nf_secret_cell,
                budget_cell,
                period_cell,
                c_old_cell.clone(),
            ],
        )?;

        // --- B1-4: bind the three hashes to public instance rows ---
        layouter.constrain_instance(c_old_cell.cell(), config.instance, 4)?;
        layouter.constrain_instance(c_new_cell.cell(), config.instance, 5)?;
        layouter.constrain_instance(nullifier_cell.cell(), config.instance, 6)?;
        // Row 7 (P) is intentionally left unconstrained: Coordinator-only check.

        Ok(())
    }
}

/// One Poseidon hash using the frozen chip/spec. A fresh chip is constructed
/// per hash because `Pow5Chip` is not `Clone` (its config is).
fn poseidon_hash<const L: usize>(
    config: &StateTransitionConfig,
    layouter: &mut impl Layouter<Fp>,
    namespace: &'static str,
    message: [AssignedCell<Fp, Fp>; L],
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let chip = Pow5Chip::construct(config.poseidon.clone());
    let hasher = Hash::<_, _, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init(
        chip,
        layouter.namespace(|| namespace),
    )?;
    hasher.hash(layouter.namespace(|| "hash"), message)
}
