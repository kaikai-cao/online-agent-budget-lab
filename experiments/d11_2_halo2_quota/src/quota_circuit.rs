//! D11.2 — minimal Halo2 circuit for the budget relation  u + c + s = Q.
//!
//! Public inputs (single instance column):
//!   instance[0] = Q   (quota,      must be nonzero, 32-bit)
//!   instance[1] = c   (cost,       must be nonzero, 32-bit)
//!
//! Private witness (advice columns):
//!   u = spent_before (32-bit)
//!   s = slack = Q - u - c (32-bit, nonnegative)
//!
//! The circuit enforces, entirely inside Halo2 gates (no host-side `if`):
//!   1. 32-bit boolean bit-decomposition of Q, c, u, s.
//!   2. Q * Q^{-1} = 1   (quota nonzero witness).
//!   3. c * c^{-1} = 1   (cost nonzero witness).
//!   4. u + c + s - Q = 0.
//!
//! Because 3 * (2^32 - 1) < 2^34 << |Fp|, the field equality is an exact
//! integer equality: no modular wraparound can fake a valid budget.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Instance,
        Selector,
    },
    poly::Rotation,
};

use halo2_proofs::pasta::Fp;

/// Number of bits each public/private value is decomposed into.
pub const BITS: usize = 32;
/// k for `Params::new(k)`: 2^8 = 256 rows, enough for 4 decompositions of 32 rows each.
pub const K: u32 = 8;

/// A value and its 32-bit decomposition occupy 32 rows in a dedicated region.
/// We assign four such regions (Q, c, u, s), then a fifth "equation" row.
#[derive(Clone, Debug)]
pub struct QuotaConfig {
    /// Single instance column: row 0 = Q, row 1 = c.
    instance: Column<Instance>,
    /// Advice column holding the value under decomposition at offset 0.
    value: Column<Advice>,
    /// Advice column holding decomposition bits b_0..b_31 (at offsets 0..31).
    bits: Column<Advice>,
    /// Advice column holding x^{-1} for the nonzero check (at offset 0).
    inv: Column<Advice>,
    /// Enables boolean check on each bit row.
    q_bool: Selector,
    /// Enables value == sum(b_i * 2^i) at offset 0.
    q_decompose: Selector,
    /// Enables x * x^{-1} = 1 at offset 0.
    q_nonzero: Selector,
    /// Enables the budget equation on the equation region.
    q_equation: Selector,
}

/// Circuit implementing  u + c + s = Q  with 32-bit range constraints.
#[derive(Clone, Debug, Default)]
pub struct QuotaCircuit {
    /// Quota Q (public via instance, but kept here to build witness/assignment).
    pub quota: u64,
    /// Cost c (public via instance).
    pub cost: u64,
    /// Spent-before u (private).
    pub spent_before: u64,
    /// Slack s = Q - u - c (private).
    pub slack: u64,
}

impl QuotaCircuit {
    /// Build a circuit from the four values. `slack` is supplied by the caller
    /// (in a real system it is computed as Q - u - c and kept private).
    pub fn new(quota: u64, cost: u64, spent_before: u64, slack: u64) -> Self {
        Self {
            quota,
            cost,
            spent_before,
            slack,
        }
    }

    /// Convenience: derive slack when the relation holds over the integers.
    /// Returns None when u + c > Q (no nonnegative slack exists in uint32).
    pub fn with_derived_slack(quota: u64, cost: u64, spent_before: u64) -> Option<Self> {
        let slack = quota.checked_sub(spent_before)?.checked_sub(cost)?;
        if slack > u32::MAX as u64 {
            return None;
        }
        Some(Self::new(quota, cost, spent_before, slack))
    }

    /// The two public inputs as field elements, in instance order [Q, c].
    pub fn public_inputs(&self) -> [Fp; 2] {
        [Fp::from(self.quota), Fp::from(self.cost)]
    }
}

/// Assign a u64 (guaranteed <= 2^32-1 by caller) plus boolean decomposition.
fn assign_decomposition_u64(
    region: &mut Region<'_, Fp>,
    config: &QuotaConfig,
    raw: u64,
    check_nonzero: bool,
    annotation: &'static str,
) -> Result<AssignedCell<Fp, Fp>, Error> {
    let value_f = Fp::from(raw);

    // value at offset 0
    let value_cell = region.assign_advice(
        || format!("{annotation} value"),
        config.value,
        0,
        || Value::known(value_f),
    )?;

    // inverse at offset 0 (for nonzero check). If raw == 0 we still assign 0;
    // the gate x * x^{-1} = 1 will then be unsatisfied, which is what we want.
    if check_nonzero {
        let inv = value_f.invert().unwrap_or_else(|| Fp::ZERO);
        region.assign_advice(
            || format!("{annotation} inv"),
            config.inv,
            0,
            || Value::known(inv),
        )?;
        config.q_nonzero.enable(region, 0)?;
    }

    // 32 decomposition bits at offsets 0..31
    for i in 0..BITS {
        let bit = (raw >> i) & 1;
        region.assign_advice(
            || format!("{annotation} bit[{i}]"),
            config.bits,
            i,
            || Value::known(Fp::from(bit)),
        )?;
        config.q_bool.enable(region, i)?;
    }
    config.q_decompose.enable(region, 0)?;

    Ok(value_cell)
}

impl Circuit<Fp> for QuotaCircuit {
    type Config = QuotaConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        // Structure must be identical; only the witness values are stripped.
        // Q and c are public but must be present to keep the same shape.
        Self {
            quota: 0,
            cost: 0,
            spent_before: 0,
            slack: 0,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let value = meta.advice_column();
        let bits = meta.advice_column();
        let inv = meta.advice_column();
        meta.enable_equality(value);
        meta.enable_equality(bits);

        let q_bool = meta.selector();
        let q_decompose = meta.selector();
        let q_nonzero = meta.selector();
        let q_equation = meta.selector();

        // Constraint 1: each bit is boolean, b * (1 - b) = 0.
        meta.create_gate("bit is boolean", |meta| {
            let s = meta.query_selector(q_bool);
            let b = meta.query_advice(bits, Rotation::cur());
            Constraints::with_selector(s, [b.clone() * (Expression::Constant(Fp::ONE) - b)])
        });

        // Constraint 2: value == sum_{i=0..31} b_i * 2^i  (32-bit range).
        meta.create_gate("32-bit decomposition", |meta| {
            let s = meta.query_selector(q_decompose);
            let v = meta.query_advice(value, Rotation::cur());
            let sum = (0..BITS).fold(Expression::Constant(Fp::ZERO), |acc, i| {
                let b = meta.query_advice(bits, Rotation(i as i32));
                acc + b * Expression::Constant(Fp::from(1u64 << i))
            });
            Constraints::with_selector(s, [v - sum])
        });

        // Constraint 3: x * x^{-1} = 1 (x != 0).
        meta.create_gate("nonzero", |meta| {
            let s = meta.query_selector(q_nonzero);
            let x = meta.query_advice(value, Rotation::cur());
            let xinv = meta.query_advice(inv, Rotation::cur());
            Constraints::with_selector(s, [x * xinv - Expression::Constant(Fp::ONE)])
        });

        // Constraint 4: budget relation, Q - u - c - s = 0, all on one row.
        meta.create_gate("budget u + c + s = Q", |meta| {
            let sel = meta.query_selector(q_equation);
            let q = meta.query_advice(value, Rotation(0));
            let c = meta.query_advice(value, Rotation(1));
            let u = meta.query_advice(value, Rotation(2));
            let s = meta.query_advice(value, Rotation(3));
            Constraints::with_selector(sel, [q - c - u - s])
        });

        QuotaConfig {
            instance,
            value,
            bits,
            inv,
            q_bool,
            q_decompose,
            q_nonzero,
            q_equation,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Four decomposition regions: Q, c, u, s. Each occupies 32 rows.
        let q_cell = layouter.assign_region(
            || "decompose Q",
            |mut region| assign_decomposition_u64(&mut region, &config, self.quota, true, "Q"),
        )?;
        let c_cell = layouter.assign_region(
            || "decompose c",
            |mut region| assign_decomposition_u64(&mut region, &config, self.cost, true, "c"),
        )?;
        let u_cell = layouter.assign_region(
            || "decompose u",
            |mut region| {
                assign_decomposition_u64(&mut region, &config, self.spent_before, false, "u")
            },
        )?;
        let s_cell = layouter.assign_region(
            || "decompose s",
            |mut region| assign_decomposition_u64(&mut region, &config, self.slack, false, "s"),
        )?;

        // Bind Q and c to the single instance column: instance[0]=Q, instance[1]=c.
        layouter.constrain_instance(q_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(c_cell.cell(), config.instance, 1)?;

        // Equation region: copy Q,c,u,s into four consecutive rows of `value`
        // and enforce Q - u - c - s = 0. Note order matches the gate:
        // row0=Q, row1=c, row2=u, row3=s.
        layouter.assign_region(
            || "budget equation",
            |mut region: Region<'_, Fp>| {
                config.q_equation.enable(&mut region, 0)?;
                let _q = q_cell.copy_advice(|| "eq Q", &mut region, config.value, 0)?;
                let _c = c_cell.copy_advice(|| "eq c", &mut region, config.value, 1)?;
                let _u = u_cell.copy_advice(|| "eq u", &mut region, config.value, 2)?;
                let _s = s_cell.copy_advice(|| "eq s", &mut region, config.value, 3)?;
                Ok(())
            },
        )?;

        Ok(())
    }
}
