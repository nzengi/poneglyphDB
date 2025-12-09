//! Logical gates (4.2: AND, OR, NOT, XOR, NAND, NOR)
//!
//! Implements custom logical gates for efficient SQL WHERE clause evaluation.
//! These gates handle boolean operations in finite fields.

use crate::circuit::types::Field;
use halo2::{
    arithmetic::Field as _,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

/// AND gate configuration
///
/// Computes: a AND b = result
///
/// Constraints:
///   - a · (1 - a) = 0 (a is boolean)
///   - b · (1 - b) = 0 (b is boolean)
///   - a · b - result = 0 (result = a AND b)
///
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct AndConfig {
    /// Advice columns for inputs and output
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
}

impl AndConfig {
    /// Configure the AND gate
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.create_gate("and", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let result = meta.query_advice(advice[0], Rotation::next());
            let s = meta.query_selector(selector);

            let one = Expression::Constant(Field::ONE);

            vec![
                // Boolean constraint for a: a · (1 - a) = 0
                s.clone() * (a.clone() * (one.clone() - a.clone())),
                // Boolean constraint for b: b · (1 - b) = 0
                s.clone() * (b.clone() * (one.clone() - b.clone())),
                // AND constraint: a · b - result = 0
                s * (a * b - result),
            ]
        });

        Self { advice, selector }
    }

    /// Assign values to the AND gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "and",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;

                // Compute result: a AND b = a · b
                let result = a_cell.value().copied() * b_cell.value();
                let result_cell =
                    region.assign_advice(|| "result", self.advice[0], 1, || result)?;

                Ok(result_cell)
            },
        )
    }
}

/// OR gate configuration
///
/// Computes: a OR b = result
///
/// Constraints:
///   - a · (1 - a) = 0 (a is boolean)
///   - b · (1 - b) = 0 (b is boolean)
///   - a + b - a · b - result = 0 (result = a OR b)
///
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct OrConfig {
    /// Advice columns for inputs and output
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
}

impl OrConfig {
    /// Configure the OR gate
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.create_gate("or", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let result = meta.query_advice(advice[0], Rotation::next());
            let s = meta.query_selector(selector);

            let one = Expression::Constant(Field::ONE);

            vec![
                // Boolean constraint for a: a · (1 - a) = 0
                s.clone() * (a.clone() * (one.clone() - a.clone())),
                // Boolean constraint for b: b · (1 - b) = 0
                s.clone() * (b.clone() * (one.clone() - b.clone())),
                // OR constraint: a + b - a · b - result = 0
                s * (a.clone() + b.clone() - a * b - result),
            ]
        });

        Self { advice, selector }
    }

    /// Assign values to the OR gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "or",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;

                // Compute result: a OR b = a + b - a · b
                let result = a_cell.value().copied() + b_cell.value()
                    - (a_cell.value().copied() * b_cell.value());
                let result_cell =
                    region.assign_advice(|| "result", self.advice[0], 1, || result)?;

                Ok(result_cell)
            },
        )
    }
}

/// NOT gate configuration
///
/// Computes: NOT a = result
///
/// Constraints:
///   - a · (1 - a) = 0 (a is boolean)
///   - 1 - a - result = 0 (result = NOT a)
///
/// Degree: 1 (linear)
#[derive(Clone, Debug)]
pub struct NotConfig {
    /// Advice columns for input and output
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
}

impl NotConfig {
    /// Configure the NOT gate
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.create_gate("not", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let result = meta.query_advice(advice[0], Rotation::next());
            let s = meta.query_selector(selector);

            let one = Expression::Constant(Field::ONE);

            vec![
                // Boolean constraint for a: a · (1 - a) = 0
                s.clone() * (a.clone() * (one.clone() - a.clone())),
                // NOT constraint: 1 - a - result = 0
                s * (one - a - result),
            ]
        });

        Self { advice, selector }
    }

    /// Assign values to the NOT gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "not",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;

                // Compute result: NOT a = 1 - a
                let result = a_cell.value().map(|a| Field::ONE - a);
                let result_cell =
                    region.assign_advice(|| "result", self.advice[0], 1, || result)?;

                Ok(result_cell)
            },
        )
    }
}

/// XOR gate configuration
///
/// Computes: a XOR b = result
///
/// Constraints:
///   - a · (1 - a) = 0 (a is boolean)
///   - b · (1 - b) = 0 (b is boolean)
///   - a + b - 2 · a · b - result = 0 (result = a XOR b)
///
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct XorConfig {
    /// Advice columns for inputs and output
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
}

impl XorConfig {
    /// Configure the XOR gate
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.create_gate("xor", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let result = meta.query_advice(advice[0], Rotation::next());
            let s = meta.query_selector(selector);

            let one = Expression::Constant(Field::ONE);
            let two = Expression::Constant(Field::from(2u64));

            vec![
                // Boolean constraint for a: a · (1 - a) = 0
                s.clone() * (a.clone() * (one.clone() - a.clone())),
                // Boolean constraint for b: b · (1 - b) = 0
                s.clone() * (b.clone() * (one.clone() - b.clone())),
                // XOR constraint: a + b - 2 · a · b - result = 0
                s * (a.clone() + b.clone() - two * a * b - result),
            ]
        });

        Self { advice, selector }
    }

    /// Assign values to the XOR gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "xor",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;

                // Compute result: a XOR b = a + b - 2 · a · b
                let result = (a_cell.value().copied() * b_cell.value())
                    .zip(a_cell.value().copied())
                    .zip(b_cell.value())
                    .map(|((product, a), b)| {
                        let two = Field::from(2u64);
                        a + b - (two * product)
                    });
                let result_cell =
                    region.assign_advice(|| "result", self.advice[0], 1, || result)?;

                Ok(result_cell)
            },
        )
    }
}

/// NAND gate configuration
///
/// Computes: NAND(a, b) = result
///
/// Constraints:
///   - a · (1 - a) = 0 (a is boolean)
///   - b · (1 - b) = 0 (b is boolean)
///   - 1 - a · b - result = 0 (result = NAND(a, b))
///
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct NandConfig {
    /// Advice columns for inputs and output
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
}

impl NandConfig {
    /// Configure the NAND gate
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.create_gate("nand", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let result = meta.query_advice(advice[0], Rotation::next());
            let s = meta.query_selector(selector);

            let one = Expression::Constant(Field::ONE);

            vec![
                // Boolean constraint for a: a · (1 - a) = 0
                s.clone() * (a.clone() * (one.clone() - a.clone())),
                // Boolean constraint for b: b · (1 - b) = 0
                s.clone() * (b.clone() * (one.clone() - b.clone())),
                // NAND constraint: 1 - a · b - result = 0
                s * (one - a * b - result),
            ]
        });

        Self { advice, selector }
    }

    /// Assign values to the NAND gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "nand",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;

                // Compute result: NAND(a, b) = 1 - a · b
                let result =
                    (a_cell.value().copied() * b_cell.value()).map(|product| Field::ONE - product);
                let result_cell =
                    region.assign_advice(|| "result", self.advice[0], 1, || result)?;

                Ok(result_cell)
            },
        )
    }
}

/// NOR gate configuration
///
/// Computes: NOR(a, b) = result
///
/// Constraints:
///   - a · (1 - a) = 0 (a is boolean)
///   - b · (1 - b) = 0 (b is boolean)
///   - 1 - a - b + a · b - result = 0 (result = NOR(a, b))
///
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct NorConfig {
    /// Advice columns for inputs and output
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
}

impl NorConfig {
    /// Configure the NOR gate
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.create_gate("nor", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let result = meta.query_advice(advice[0], Rotation::next());
            let s = meta.query_selector(selector);

            let one = Expression::Constant(Field::ONE);

            vec![
                // Boolean constraint for a: a · (1 - a) = 0
                s.clone() * (a.clone() * (one.clone() - a.clone())),
                // Boolean constraint for b: b · (1 - b) = 0
                s.clone() * (b.clone() * (one.clone() - b.clone())),
                // NOR constraint: 1 - a - b + a · b - result = 0
                s * (one - a.clone() - b.clone() + a * b - result),
            ]
        });

        Self { advice, selector }
    }

    /// Assign values to the NOR gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "nor",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;

                // Compute result: NOR(a, b) = 1 - a - b + a · b
                let result = (a_cell.value().copied() * b_cell.value())
                    .zip(a_cell.value().copied())
                    .zip(b_cell.value())
                    .map(|((product, a), b)| Field::ONE - a - b + product);
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
        and: Option<(Field, Field)>,
        or: Option<(Field, Field)>,
        not: Option<Field>,
        xor: Option<(Field, Field)>,
        nand: Option<(Field, Field)>,
        nor: Option<(Field, Field)>,
    }

    impl Circuit<Field> for TestCircuit {
        type Config = (
            AndConfig,
            OrConfig,
            NotConfig,
            XorConfig,
            NandConfig,
            NorConfig,
        );
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                and: None,
                or: None,
                not: None,
                xor: None,
                nand: None,
                nor: None,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            let and = AndConfig::configure(meta);
            let or = OrConfig::configure(meta);
            let not = NotConfig::configure(meta);
            let xor = XorConfig::configure(meta);
            let nand = NandConfig::configure(meta);
            let nor = NorConfig::configure(meta);

            (and, or, not, xor, nand, nor)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            if let Some((a, b)) = self.and {
                config.0.assign(
                    layouter.namespace(|| "and"),
                    Value::known(a),
                    Value::known(b),
                )?;
            }

            if let Some((a, b)) = self.or {
                config.1.assign(
                    layouter.namespace(|| "or"),
                    Value::known(a),
                    Value::known(b),
                )?;
            }

            if let Some(a) = self.not {
                config.2.assign(layouter.namespace(|| "not"), Value::known(a))?;
            }

            if let Some((a, b)) = self.xor {
                config.3.assign(
                    layouter.namespace(|| "xor"),
                    Value::known(a),
                    Value::known(b),
                )?;
            }

            if let Some((a, b)) = self.nand {
                config.4.assign(
                    layouter.namespace(|| "nand"),
                    Value::known(a),
                    Value::known(b),
                )?;
            }

            if let Some((a, b)) = self.nor {
                config.5.assign(
                    layouter.namespace(|| "nor"),
                    Value::known(a),
                    Value::known(b),
                )?;
            }

            Ok(())
        }
    }

    #[test]
    fn test_and_gate() {
        let k = 4;

        // Test all truth table combinations
        let test_cases = vec![
            (Field::ZERO, Field::ZERO, Field::ZERO),
            (Field::ZERO, Field::ONE, Field::ZERO),
            (Field::ONE, Field::ZERO, Field::ZERO),
            (Field::ONE, Field::ONE, Field::ONE),
        ];

        for (a, b, _expected) in test_cases {
            let circuit = TestCircuit {
                and: Some((a, b)),
                or: None,
                not: None,
                xor: None,
                nand: None,
                nor: None,
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[test]
    fn test_or_gate() {
        let k = 4;

        // Test all truth table combinations
        let test_cases = vec![
            (Field::ZERO, Field::ZERO, Field::ZERO),
            (Field::ZERO, Field::ONE, Field::ONE),
            (Field::ONE, Field::ZERO, Field::ONE),
            (Field::ONE, Field::ONE, Field::ONE),
        ];

        for (a, b, _expected) in test_cases {
            let circuit = TestCircuit {
                and: None,
                or: Some((a, b)),
                not: None,
                xor: None,
                nand: None,
                nor: None,
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[test]
    fn test_not_gate() {
        let k = 4;

        // Test truth table
        let test_cases = vec![(Field::ZERO, Field::ONE), (Field::ONE, Field::ZERO)];

        for (a, _expected) in test_cases {
            let circuit = TestCircuit {
                and: None,
                or: None,
                not: Some(a),
                xor: None,
                nand: None,
                nor: None,
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[test]
    fn test_xor_gate() {
        let k = 4;

        // Test all truth table combinations
        let test_cases = vec![
            (Field::ZERO, Field::ZERO, Field::ZERO),
            (Field::ZERO, Field::ONE, Field::ONE),
            (Field::ONE, Field::ZERO, Field::ONE),
            (Field::ONE, Field::ONE, Field::ZERO),
        ];

        for (a, b, _expected) in test_cases {
            let circuit = TestCircuit {
                and: None,
                or: None,
                not: None,
                xor: Some((a, b)),
                nand: None,
                nor: None,
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[test]
    fn test_nand_gate() {
        let k = 4;

        // Test all truth table combinations
        let test_cases = vec![
            (Field::ZERO, Field::ZERO, Field::ONE),
            (Field::ZERO, Field::ONE, Field::ONE),
            (Field::ONE, Field::ZERO, Field::ONE),
            (Field::ONE, Field::ONE, Field::ZERO),
        ];

        for (a, b, _expected) in test_cases {
            let circuit = TestCircuit {
                and: None,
                or: None,
                not: None,
                xor: None,
                nand: Some((a, b)),
                nor: None,
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[test]
    fn test_nor_gate() {
        let k = 4;

        // Test all truth table combinations
        let test_cases = vec![
            (Field::ZERO, Field::ZERO, Field::ONE),
            (Field::ZERO, Field::ONE, Field::ZERO),
            (Field::ONE, Field::ZERO, Field::ZERO),
            (Field::ONE, Field::ONE, Field::ZERO),
        ];

        for (a, b, _expected) in test_cases {
            let circuit = TestCircuit {
                and: None,
                or: None,
                not: None,
                xor: None,
                nand: None,
                nor: Some((a, b)),
            };

            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[test]
    fn test_all_gates() {
        let k = 4;

        let circuit = TestCircuit {
            and: Some((Field::ONE, Field::ONE)),
            or: Some((Field::ZERO, Field::ONE)),
            not: Some(Field::ZERO),
            xor: Some((Field::ONE, Field::ZERO)),
            nand: Some((Field::ZERO, Field::ZERO)),
            nor: Some((Field::ZERO, Field::ZERO)),
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
