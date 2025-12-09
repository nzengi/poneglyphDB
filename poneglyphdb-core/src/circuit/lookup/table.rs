//! Lookup table implementation
//!
//! Provides generic structures for configuring and loading values into lookup tables.
//! Crucial for optimizing Range Checks, Bitwise operations, and complex function mappings.

use crate::circuit::types::Field;
use halo2::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};

/// Configuration for a single-column lookup table.
/// Used for Range Checks (e.g., verifying a value is within [0, 2^N)).
#[derive(Clone, Debug)]
pub struct LookupTableConfig {
    /// The single table column.
    pub column: TableColumn,
}

impl LookupTableConfig {
    /// Configure a new single-column lookup table.
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let column = meta.lookup_table_column();
        Self { column }
    }

    /// Load values into the lookup table.
    ///
    /// This function assigns values to the table column. It is typically called
    /// during circuit synthesis to populate the table with valid values
    /// (e.g., all numbers from 0 to 255 for a byte check).
    pub fn load(&self, mut layouter: impl Layouter<Field>, values: &[Field]) -> Result<(), Error> {
        layouter.assign_table(
            || "load lookup table",
            |mut table| {
                for (offset, value) in values.iter().enumerate() {
                    table.assign_cell(
                        || format!("table cell {}", offset),
                        self.column,
                        offset,
                        || Value::known(*value),
                    )?;
                }
                Ok(())
            },
        )
    }
}

/// Configuration for a multi-column lookup table.
/// Used for mapping inputs to outputs, like Bitwise XOR (input1, input2, output).
/// `N` is the number of columns.
#[derive(Clone, Debug)]
pub struct MultiColLookupTableConfig<const N: usize> {
    /// The table columns.
    pub columns: [TableColumn; N],
}

impl<const N: usize> MultiColLookupTableConfig<N> {
    /// Configure a new multi-column lookup table.
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let columns = [0; N].map(|_| meta.lookup_table_column());
        Self { columns }
    }

    /// Load rows into the multi-column lookup table.
    ///
    /// `values` is a slice of arrays, where each array represents a row [col0, col1, ...].
    pub fn load(
        &self,
        mut layouter: impl Layouter<Field>,
        values: &[[Field; N]],
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "load multi-col lookup table",
            |mut table| {
                for (row_idx, row_values) in values.iter().enumerate() {
                    for (col_idx, &value) in row_values.iter().enumerate() {
                        table.assign_cell(
                            || format!("table cell row {} col {}", row_idx, col_idx),
                            self.columns[col_idx],
                            row_idx,
                            || Value::known(value),
                        )?;
                    }
                }
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        plonk::{Advice, Circuit, Column, Selector},
        poly::Rotation,
    };

    // Example Circuit to test LookupTable
    struct TestCircuit {
        table_values: Vec<Field>,
        input_value: Field,
    }

    #[derive(Clone, Debug)]
    struct TestConfig {
        table_config: LookupTableConfig,
        advice: Column<Advice>,
        selector: Selector,
    }

    impl Circuit<Field> for TestCircuit {
        type Config = TestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                table_values: vec![],
                input_value: Field::ZERO,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            let table_config = LookupTableConfig::configure(meta);
            let advice = meta.advice_column();
            let selector = meta.complex_selector();

            meta.enable_equality(advice);

            // Lookup Argument: Check if 'advice' value exists in 'table_config.column'
            meta.lookup("test lookup", |meta| {
                let s = meta.query_selector(selector);
                let val = meta.query_advice(advice, Rotation::cur());
                vec![(s * val, table_config.column)]
            });

            TestConfig {
                table_config,
                advice,
                selector,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            // Load Table
            config
                .table_config
                .load(layouter.namespace(|| "load table"), &self.table_values)?;

            // Assign Advice
            layouter.assign_region(
                || "assign input",
                |mut region| {
                    config.selector.enable(&mut region, 0)?;
                    region.assign_advice(
                        || "input",
                        config.advice,
                        0,
                        || Value::known(self.input_value),
                    )?;
                    Ok(())
                },
            )?;

            Ok(())
        }
    }

    #[test]
    fn test_lookup_table_valid() {
        let k = 5;
        let table_values = vec![Field::from(1), Field::from(2), Field::from(3)];
        let input_value = Field::from(2); // 2 is in [1, 2, 3]

        let circuit = TestCircuit {
            table_values,
            input_value,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_lookup_table_invalid() {
        let k = 5;
        let table_values = vec![Field::from(1), Field::from(2), Field::from(3)];
        let input_value = Field::from(99); // 99 is NOT in [1, 2, 3]

        let circuit = TestCircuit {
            table_values,
            input_value,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
}
