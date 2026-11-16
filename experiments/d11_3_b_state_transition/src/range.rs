//! uint32 range constraints reused from D11.2 (`quota_circuit.rs`).
//!
//! A value `x` is range-constrained by
//!   `x = sum_{i=0..31} b_i * 2^i`,  `b_i * (b_i - 1) = 0`
//! entirely inside Halo2 gates. An optional inversion witness enforces `x != 0`.
//!
//! Host-side checks are never used to reject a value: a 2^32 input is assigned
//! with all 32 bits zero, so the decomposition gate fails in `MockProver`.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Region},
    pasta::Fp,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};

pub const BITS: usize = 32;
pub const U32_MAX: u64 = u32::MAX as u64;

#[derive(Clone, Debug)]
pub struct RangeConfig {
    pub value: Column<Advice>,
    pub bits: Column<Advice>,
    pub inv: Column<Advice>,
    q_bool: Selector,
    q_decompose: Selector,
    q_nonzero: Selector,
}

impl RangeConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let value = meta.advice_column();
        let bits = meta.advice_column();
        let inv = meta.advice_column();
        meta.enable_equality(value);
        meta.enable_equality(bits);

        let q_bool = meta.selector();
        let q_decompose = meta.selector();
        let q_nonzero = meta.selector();

        meta.create_gate("bit is boolean", |meta| {
            let s = meta.query_selector(q_bool);
            let b = meta.query_advice(bits, Rotation::cur());
            Constraints::with_selector(s, [b.clone() * (Expression::Constant(Fp::ONE) - b)])
        });

        meta.create_gate("32-bit decomposition", |meta| {
            let s = meta.query_selector(q_decompose);
            let v = meta.query_advice(value, Rotation::cur());
            let sum = (0..BITS).fold(Expression::Constant(Fp::ZERO), |acc, i| {
                let b = meta.query_advice(bits, Rotation(i as i32));
                acc + b * Expression::Constant(Fp::from(1u64 << i))
            });
            Constraints::with_selector(s, [v - sum])
        });

        meta.create_gate("nonzero", |meta| {
            let s = meta.query_selector(q_nonzero);
            let x = meta.query_advice(value, Rotation::cur());
            let xinv = meta.query_advice(inv, Rotation::cur());
            Constraints::with_selector(s, [x * xinv - Expression::Constant(Fp::ONE)])
        });

        RangeConfig {
            value,
            bits,
            inv,
            q_bool,
            q_decompose,
            q_nonzero,
        }
    }

    /// Assign `raw` in a 32-row region and return its constrained value cell.
    /// `check_nonzero` adds the inversion constraint (used for Q and c).
    pub fn assign_u32(
        &self,
        region: &mut Region<'_, Fp>,
        raw: u64,
        check_nonzero: bool,
        annotation: &'static str,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let value_f = Fp::from(raw);
        let value_cell = region.assign_advice(
            || format!("{annotation} value"),
            self.value,
            0,
            || halo2_proofs::circuit::Value::known(value_f),
        )?;

        if check_nonzero {
            let inv = value_f.invert().unwrap_or_else(|| Fp::ZERO);
            region.assign_advice(
                || format!("{annotation} inv"),
                self.inv,
                0,
                || halo2_proofs::circuit::Value::known(inv),
            )?;
            self.q_nonzero.enable(region, 0)?;
        }

        for i in 0..BITS {
            let bit = (raw >> i) & 1;
            region.assign_advice(
                || format!("{annotation} bit[{i}]"),
                self.bits,
                i,
                || halo2_proofs::circuit::Value::known(Fp::from(bit)),
            )?;
            self.q_bool.enable(region, i)?;
        }
        self.q_decompose.enable(region, 0)?;

        Ok(value_cell)
    }
}
