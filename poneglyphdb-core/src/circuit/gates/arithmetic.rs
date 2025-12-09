//! Arithmetic gates (4.1: Multi-Add, Multi-Multiply, MAC)
//!
//! Implements custom arithmetic gates for efficient SQL query verification.
//! These gates reduce circuit size and proof generation time by combining
//! multiple operations into single gates.

use crate::circuit::types::Field;
use halo2::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

/// Multi-Add gate configuration
///
/// Supports adding up to 4 inputs in a single gate.
/// Constraint: a + b + c + d - result = 0
/// Degree: 1 (linear)
#[derive(Clone, Debug)]
pub struct MultiAddConfig {
    /// Advice columns for inputs and output
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
}

impl MultiAddConfig {
    /// Configure the Multi-Add gate
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.create_gate("multi_add", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[0], Rotation::next());
            let d = meta.query_advice(advice[1], Rotation::next());
            let result = meta.query_advice(advice[0], Rotation(2));
            let s = meta.query_selector(selector);

            vec![s * (a + b + c + d - result)]
        });

        Self { advice, selector }
    }

    /// Assign values to the Multi-Add gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
        c: Value<Field>,
        d: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "multi_add",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;
                let c_cell = region.assign_advice(|| "c", self.advice[0], 1, || c)?;
                let d_cell = region.assign_advice(|| "d", self.advice[1], 1, || d)?;

                let result =
                    a_cell.value().copied() + b_cell.value() + c_cell.value() + d_cell.value();

                let result_cell =
                    region.assign_advice(|| "result", self.advice[0], 2, || result)?;

                Ok(result_cell)
            },
        )
    }
}

/// MAC (Multiply-Accumulate) gate configuration
///
/// Computes: a * b + c = result
/// Constraint: a * b + c - result = 0
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct MacConfig {
    /// Advice columns for inputs and output
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
}

impl MacConfig {
    /// Configure the MAC gate
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.create_gate("mac", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[0], Rotation::next());
            let result = meta.query_advice(advice[1], Rotation::next());
            let s = meta.query_selector(selector);

            vec![s * (a * b + c - result)]
        });

        Self { advice, selector }
    }

    /// Assign values to the MAC gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
        c: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "mac",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;
                let c_cell = region.assign_advice(|| "c", self.advice[0], 1, || c)?;

                let result = a_cell.value().copied() * b_cell.value() + c_cell.value();

                let result_cell =
                    region.assign_advice(|| "result", self.advice[1], 1, || result)?;

                Ok(result_cell)
            },
        )
    }
}

/// Multi-Multiply gate configuration
///
/// Computes: a * b = result (2 inputs)
/// Constraint: a * b - result = 0
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct MultiMultiplyConfig {
    /// Advice columns for inputs and output
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
}

impl MultiMultiplyConfig {
    /// Configure the Multi-Multiply gate
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.create_gate("multi_multiply", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let result = meta.query_advice(advice[0], Rotation::next());
            let s = meta.query_selector(selector);

            vec![s * (a * b - result)]
        });

        Self { advice, selector }
    }

    /// Assign values to the Multi-Multiply gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "multi_multiply",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;

                let result = a_cell.value().copied() * b_cell.value();

                let result_cell =
                    region.assign_advice(|| "result", self.advice[0], 1, || result)?;

                Ok(result_cell)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

    struct TestCircuit {
        multi_add: Option<(Field, Field, Field, Field)>,
        mac: Option<(Field, Field, Field)>,
        multi_mul: Option<(Field, Field)>,
    }

    impl Circuit<Field> for TestCircuit {
        type Config = (MultiAddConfig, MacConfig, MultiMultiplyConfig);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                multi_add: None,
                mac: None,
                multi_mul: None,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            let multi_add = MultiAddConfig::configure(meta);
            let mac = MacConfig::configure(meta);
            let multi_mul = MultiMultiplyConfig::configure(meta);

            (multi_add, mac, multi_mul)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            if let Some((a, b, c, d)) = self.multi_add {
                config.0.assign(
                    layouter.namespace(|| "multi_add"),
                    Value::known(a),
                    Value::known(b),
                    Value::known(c),
                    Value::known(d),
                )?;
            }

            if let Some((a, b, c)) = self.mac {
                config.1.assign(
                    layouter.namespace(|| "mac"),
                    Value::known(a),
                    Value::known(b),
                    Value::known(c),
                )?;
            }

            if let Some((a, b)) = self.multi_mul {
                config.2.assign(
                    layouter.namespace(|| "multi_mul"),
                    Value::known(a),
                    Value::known(b),
                )?;
            }

            Ok(())
        }
    }

    #[test]
    fn test_multi_add_gate() {
        let circuit = TestCircuit {
            multi_add: Some((
                Field::from(1u64),
                Field::from(2u64),
                Field::from(3u64),
                Field::from(4u64),
            )),
            mac: None,
            multi_mul: None,
        };

        let k = 4;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_mac_gate() {
        let circuit = TestCircuit {
            multi_add: None,
            mac: Some((Field::from(2u64), Field::from(3u64), Field::from(4u64))),
            multi_mul: None,
        };

        let k = 4;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_multi_multiply_gate() {
        let circuit = TestCircuit {
            multi_add: None,
            mac: None,
            multi_mul: Some((Field::from(5u64), Field::from(6u64))),
        };

        let k = 4;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_all_gates() {
        let circuit = TestCircuit {
            multi_add: Some((
                Field::from(1u64),
                Field::from(2u64),
                Field::from(3u64),
                Field::from(4u64),
            )),
            mac: Some((Field::from(2u64), Field::from(3u64), Field::from(4u64))),
            multi_mul: Some((Field::from(5u64), Field::from(6u64))),
        };

        let k = 4;
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
