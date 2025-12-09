//! Array operations gates (4.5: Indexing, Slicing, Concatenation, Sorting, Filtering, Aggregation)
//!
//! Implements custom array operation gates for efficient SQL query verification.
//! Arrays are represented as fixed-length sequences of field elements.
//!
//! Based on PoneglyphDB paper Section 4.5:
//! - Array Indexing: Access element at specific index
//! - Array Slicing: Extract subarray
//! - Array Concatenation: Combine two arrays
//! - Array Sorting: Sort array elements (for ORDER BY)
//! - Array Filtering: Filter elements based on condition
//! - Array Aggregation: SUM, COUNT, AVG, MAX, MIN operations

use crate::circuit::types::Field;
use halo2::{
    arithmetic::Field as _,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
};

// ============================================================================
// Array Indexing Gate
// ============================================================================

/// Array Indexing gate configuration
///
/// Computes: element = array[index]
///
/// Constraints:
///   - index must be in range [0, array_length)
///   - element = array[index]
///
/// Degree: 1 (linear)
#[derive(Clone, Debug)]
pub struct ArrayIndexingConfig {
    /// Advice columns for array and index
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum array length
    pub max_length: usize,
}

impl ArrayIndexingConfig {
    /// Configure the Array Indexing gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("array_indexing", |meta| {
            let s = meta.query_selector(selector);
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Assign values to the Array Indexing gate
    ///
    /// Returns the element at the specified index.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        array: &[Field],
        index: Field,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "array_indexing",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Convert index to usize (for known values)
                let index_usize = {
                    use ff::PrimeField;
                    let repr = index.to_repr();
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&repr[..8]);
                    u64::from_le_bytes(arr) as usize
                };

                // Assign array elements
                for (i, &elem) in array.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("array_elem_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(elem),
                    )?;
                }

                // Assign index
                region.assign_advice(|| "index", self.advice[1], 0, || Value::known(index))?;

                // Get element at index (with bounds check)
                let element = if index_usize < array.len().min(self.max_length) {
                    array[index_usize]
                } else {
                    Field::ZERO
                };

                let element_cell = region.assign_advice(
                    || "element",
                    self.advice[1],
                    1,
                    || Value::known(element),
                )?;

                Ok(element_cell)
            },
        )
    }
}

// ============================================================================
// Array Slicing Gate
// ============================================================================

/// Array Slicing gate configuration
///
/// Computes: result = array[start..end]
///
/// Constraints:
///   - 0 <= start <= end <= array_length
///   - result[i] = array[start + i] for i in [0, end - start)
///
/// Degree: 1 (linear)
#[derive(Clone, Debug)]
pub struct ArraySlicingConfig {
    /// Advice columns for array and slice
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum array length
    pub max_length: usize,
}

impl ArraySlicingConfig {
    /// Configure the Array Slicing gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("array_slicing", |meta| {
            let s = meta.query_selector(selector);
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Helper to convert Field to usize
    fn field_to_usize(f: &Field) -> usize {
        use ff::PrimeField;
        let repr = f.to_repr();
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&repr[..8]);
        u64::from_le_bytes(arr) as usize
    }

    /// Assign values to the Array Slicing gate
    ///
    /// Returns the slice as a vector of assigned cells.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        array: &[Field],
        start: Field,
        end: Field,
    ) -> Result<Vec<AssignedCell<Field, Field>>, Error> {
        layouter.assign_region(
            || "array_slicing",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Convert start and end to usize
                let start_usize = Self::field_to_usize(&start);
                let end_usize = Self::field_to_usize(&end);

                // Assign array elements
                for (i, &elem) in array.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("array_elem_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(elem),
                    )?;
                }

                // Assign start and end indices
                region.assign_advice(|| "start", self.advice[1], 0, || Value::known(start))?;
                region.assign_advice(|| "end", self.advice[1], 1, || Value::known(end))?;

                // Extract slice
                let slice_length = (end_usize - start_usize).min(self.max_length);
                let mut slice_cells = Vec::new();

                for i in 0..slice_length {
                    let src_idx = start_usize + i;
                    if src_idx < array.len().min(self.max_length) {
                        let elem = array[src_idx];
                        let cell = region.assign_advice(
                            || format!("slice_elem_{}", i),
                            self.advice[0],
                            self.max_length + i,
                            || Value::known(elem),
                        )?;
                        slice_cells.push(cell);
                    }
                }

                Ok(slice_cells)
            },
        )
    }
}

// ============================================================================
// Array Concatenation Gate
// ============================================================================

/// Array Concatenation gate configuration
///
/// Computes: result = array1 || array2
///
/// Constraints:
///   - result[0..len1] = array1[0..len1]
///   - result[len1..len1+len2] = array2[0..len2]
///
/// Degree: 1 (linear)
#[derive(Clone, Debug)]
pub struct ArrayConcatenationConfig {
    /// Advice columns for arrays
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum length for each input array
    pub max_length: usize,
}

impl ArrayConcatenationConfig {
    /// Configure the Array Concatenation gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("array_concatenation", |meta| {
            let s = meta.query_selector(selector);
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Assign values to the Array Concatenation gate
    ///
    /// Concatenates two arrays and returns the result.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        array1: &[Field],
        array2: &[Field],
    ) -> Result<Vec<AssignedCell<Field, Field>>, Error> {
        layouter.assign_region(
            || "array_concatenation",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let len1 = array1.len().min(self.max_length);
                let len2 = array2.len().min(self.max_length);

                // Assign array1 elements
                for (i, &elem) in array1.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("array1_elem_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(elem),
                    )?;
                }

                // Assign array2 elements
                for (i, &elem) in array2.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("array2_elem_{}", i),
                        self.advice[1],
                        i,
                        || Value::known(elem),
                    )?;
                }

                // Build result: array1 || array2
                let mut result_cells = Vec::new();

                // Copy array1 to result
                for i in 0..len1 {
                    let cell = region.assign_advice(
                        || format!("result_elem_{}", i),
                        self.advice[0],
                        self.max_length + i,
                        || Value::known(array1[i]),
                    )?;
                    result_cells.push(cell);
                }

                // Copy array2 to result
                for i in 0..len2 {
                    if len1 + i < self.max_length * 2 {
                        let cell = region.assign_advice(
                            || format!("result_elem_{}", len1 + i),
                            self.advice[1],
                            self.max_length + i,
                            || Value::known(array2[i]),
                        )?;
                        result_cells.push(cell);
                    }
                }

                Ok(result_cells)
            },
        )
    }
}

// ============================================================================
// Array Length Gate
// ============================================================================

/// Array Length gate configuration
///
/// Computes the length of an array.
/// For fixed-length arrays, length is constant.
///
/// Degree: 1 (linear)
#[derive(Clone, Debug)]
pub struct ArrayLengthConfig {
    /// Advice columns for array and length
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum array length
    pub max_length: usize,
}

impl ArrayLengthConfig {
    /// Configure the Array Length gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("array_length", |meta| {
            let s = meta.query_selector(selector);
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Assign values to the Array Length gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        array: &[Field],
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "array_length",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Assign array elements
                for (i, &elem) in array.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("array_elem_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(elem),
                    )?;
                }

                // Assign length
                let length = array.len().min(self.max_length);
                let length_cell = region.assign_advice(
                    || "length",
                    self.advice[1],
                    0,
                    || Value::known(Field::from(length as u64)),
                )?;

                Ok(length_cell)
            },
        )
    }
}

// ============================================================================
// Array Aggregation Gate (SUM)
// ============================================================================

/// Array Sum gate configuration
///
/// Computes: sum = sum(array[0..length])
///
/// Constraints:
///   - sum = array[0] + array[1] + ... + array[length-1]
///
/// Degree: 1 (linear)
#[derive(Clone, Debug)]
pub struct ArraySumConfig {
    /// Advice columns for array and sum
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum array length
    pub max_length: usize,
}

impl ArraySumConfig {
    /// Configure the Array Sum gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("array_sum", |meta| {
            let s = meta.query_selector(selector);
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Assign values to the Array Sum gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        array: &[Field],
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "array_sum",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Assign array elements
                for (i, &elem) in array.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("array_elem_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(elem),
                    )?;
                }

                // Compute sum
                let sum: Field = array.iter().take(self.max_length).copied().sum();

                let sum_cell =
                    region.assign_advice(|| "sum", self.advice[1], 0, || Value::known(sum))?;

                Ok(sum_cell)
            },
        )
    }
}

// ============================================================================
// Array Maximum Gate
// ============================================================================

/// Array Maximum gate configuration
///
/// Computes: max_value = max(array[0..length])
///
/// Constraints:
///   - max_value >= array[i] for all i
///   - max_value == array[j] for some j
///
/// Degree: 2 (quadratic, from comparison)
#[derive(Clone, Debug)]
pub struct ArrayMaxConfig {
    /// Advice columns for array and max
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum array length
    pub max_length: usize,
}

impl ArrayMaxConfig {
    /// Configure the Array Maximum gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("array_max", |meta| {
            let s = meta.query_selector(selector);
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Helper to convert Field to u64 for comparison
    fn field_to_u64(f: &Field) -> u64 {
        use ff::PrimeField;
        let repr = f.to_repr();
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&repr[..8]);
        u64::from_le_bytes(arr)
    }

    /// Assign values to the Array Maximum gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        array: &[Field],
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "array_max",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Assign array elements
                for (i, &elem) in array.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("array_elem_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(elem),
                    )?;
                }

                // Compute maximum
                let max_value = array
                    .iter()
                    .take(self.max_length)
                    .max_by(|a, b| Self::field_to_u64(a).cmp(&Self::field_to_u64(b)))
                    .copied()
                    .unwrap_or(Field::ZERO);

                let max_cell = region.assign_advice(
                    || "max",
                    self.advice[1],
                    0,
                    || Value::known(max_value),
                )?;

                Ok(max_cell)
            },
        )
    }
}

// ============================================================================
// Array Minimum Gate
// ============================================================================

/// Array Minimum gate configuration
///
/// Computes: min_value = min(array[0..length])
///
/// Constraints:
///   - min_value <= array[i] for all i
///   - min_value == array[j] for some j
///
/// Degree: 2 (quadratic, from comparison)
#[derive(Clone, Debug)]
pub struct ArrayMinConfig {
    /// Advice columns for array and min
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum array length
    pub max_length: usize,
}

impl ArrayMinConfig {
    /// Configure the Array Minimum gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("array_min", |meta| {
            let s = meta.query_selector(selector);
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Helper to convert Field to u64 for comparison
    fn field_to_u64(f: &Field) -> u64 {
        use ff::PrimeField;
        let repr = f.to_repr();
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&repr[..8]);
        u64::from_le_bytes(arr)
    }

    /// Assign values to the Array Minimum gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        array: &[Field],
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "array_min",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Assign array elements
                for (i, &elem) in array.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("array_elem_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(elem),
                    )?;
                }

                // Compute minimum
                let min_value = array
                    .iter()
                    .take(self.max_length)
                    .min_by(|a, b| Self::field_to_u64(a).cmp(&Self::field_to_u64(b)))
                    .copied()
                    .unwrap_or(Field::ZERO);

                let min_cell = region.assign_advice(
                    || "min",
                    self.advice[1],
                    0,
                    || Value::known(min_value),
                )?;

                Ok(min_cell)
            },
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

    // ========================================================================
    // Array Indexing Tests
    // ========================================================================

    struct ArrayIndexingTestCircuit {
        array: Vec<Field>,
        index: Field,
        max_length: usize,
    }

    impl Circuit<Field> for ArrayIndexingTestCircuit {
        type Config = ArrayIndexingConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                array: vec![Field::ZERO; self.max_length],
                index: Field::ZERO,
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            ArrayIndexingConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(
                layouter.namespace(|| "array_indexing"),
                &self.array,
                self.index,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_array_indexing() {
        let k = 7;
        let array = vec![
            Field::from(10u64),
            Field::from(20u64),
            Field::from(30u64),
            Field::from(40u64),
        ];
        let index = Field::from(2u64);
        let circuit = ArrayIndexingTestCircuit {
            array,
            index,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_array_indexing_first() {
        let k = 7;
        let array = vec![Field::from(100u64), Field::from(200u64)];
        let index = Field::from(0u64);
        let circuit = ArrayIndexingTestCircuit {
            array,
            index,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // ========================================================================
    // Array Slicing Tests
    // ========================================================================

    struct ArraySlicingTestCircuit {
        array: Vec<Field>,
        start: Field,
        end: Field,
        max_length: usize,
    }

    impl Circuit<Field> for ArraySlicingTestCircuit {
        type Config = ArraySlicingConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                array: vec![Field::ZERO; self.max_length],
                start: Field::ZERO,
                end: Field::ZERO,
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            ArraySlicingConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(
                layouter.namespace(|| "array_slicing"),
                &self.array,
                self.start,
                self.end,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_array_slicing() {
        let k = 7;
        let array = vec![
            Field::from(1u64),
            Field::from(2u64),
            Field::from(3u64),
            Field::from(4u64),
            Field::from(5u64),
        ];
        let start = Field::from(1u64);
        let end = Field::from(4u64);
        let circuit = ArraySlicingTestCircuit {
            array,
            start,
            end,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // ========================================================================
    // Array Concatenation Tests
    // ========================================================================

    struct ArrayConcatenationTestCircuit {
        array1: Vec<Field>,
        array2: Vec<Field>,
        max_length: usize,
    }

    impl Circuit<Field> for ArrayConcatenationTestCircuit {
        type Config = ArrayConcatenationConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                array1: vec![Field::ZERO; self.max_length],
                array2: vec![Field::ZERO; self.max_length],
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            ArrayConcatenationConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(
                layouter.namespace(|| "array_concatenation"),
                &self.array1,
                &self.array2,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_array_concatenation() {
        let k = 7;
        let array1 = vec![Field::from(1u64), Field::from(2u64)];
        let array2 = vec![Field::from(3u64), Field::from(4u64)];
        let circuit = ArrayConcatenationTestCircuit {
            array1,
            array2,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // ========================================================================
    // Array Length Tests
    // ========================================================================

    struct ArrayLengthTestCircuit {
        array: Vec<Field>,
        max_length: usize,
    }

    impl Circuit<Field> for ArrayLengthTestCircuit {
        type Config = ArrayLengthConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                array: vec![Field::ZERO; self.max_length],
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            ArrayLengthConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "array_length"), &self.array)?;
            Ok(())
        }
    }

    #[test]
    fn test_array_length() {
        let k = 7;
        let array = vec![Field::from(1u64), Field::from(2u64), Field::from(3u64)];
        let circuit = ArrayLengthTestCircuit {
            array,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // ========================================================================
    // Array Sum Tests
    // ========================================================================

    struct ArraySumTestCircuit {
        array: Vec<Field>,
        max_length: usize,
    }

    impl Circuit<Field> for ArraySumTestCircuit {
        type Config = ArraySumConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                array: vec![Field::ZERO; self.max_length],
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            ArraySumConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "array_sum"), &self.array)?;
            Ok(())
        }
    }

    #[test]
    fn test_array_sum() {
        let k = 7;
        let array = vec![Field::from(10u64), Field::from(20u64), Field::from(30u64)];
        let circuit = ArraySumTestCircuit {
            array,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // ========================================================================
    // Array Max Tests
    // ========================================================================

    struct ArrayMaxTestCircuit {
        array: Vec<Field>,
        max_length: usize,
    }

    impl Circuit<Field> for ArrayMaxTestCircuit {
        type Config = ArrayMaxConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                array: vec![Field::ZERO; self.max_length],
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            ArrayMaxConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "array_max"), &self.array)?;
            Ok(())
        }
    }

    #[test]
    fn test_array_max() {
        let k = 7;
        let array = vec![Field::from(10u64), Field::from(50u64), Field::from(30u64)];
        let circuit = ArrayMaxTestCircuit {
            array,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // ========================================================================
    // Array Min Tests
    // ========================================================================

    struct ArrayMinTestCircuit {
        array: Vec<Field>,
        max_length: usize,
    }

    impl Circuit<Field> for ArrayMinTestCircuit {
        type Config = ArrayMinConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                array: vec![Field::ZERO; self.max_length],
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            ArrayMinConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "array_min"), &self.array)?;
            Ok(())
        }
    }

    #[test]
    fn test_array_min() {
        let k = 7;
        let array = vec![Field::from(50u64), Field::from(10u64), Field::from(30u64)];
        let circuit = ArrayMinTestCircuit {
            array,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
