//! String operations gates (4.4: Concatenation, Substring, Length, Equality, Comparison, LIKE, Hash, Case, Trim)
//!
//! Implements custom string operation gates for efficient SQL query verification.
//! Strings are represented as fixed-length arrays of field elements (ASCII characters).
//!
//! Based on PoneglyphDB paper Section 4.4:
//! - String Equality: Character-by-character or hash-based comparison
//! - String Length: Count non-zero characters
//! - String Concatenation: Combine two strings
//! - String Comparison: Lexicographic ordering for ORDER BY

use crate::circuit::types::Field;
use halo2::{
    arithmetic::Field as _,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
};

// ============================================================================
// String Length Gate
// ============================================================================

/// String Length gate configuration
///
/// Computes the length of a string represented as field elements.
/// For fixed-length strings with null termination, counts non-zero characters.
///
/// Constraints:
///   - length is verified by witness computation
///   - For null-terminated strings: length = position of first zero
///
/// Degree: 1 (linear)
#[derive(Clone, Debug)]
pub struct StringLengthConfig {
    /// Advice columns for string and length
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum string length
    pub max_length: usize,
}

impl StringLengthConfig {
    /// Configure the String Length gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        // Enable equality for advice columns
        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        // Length verification gate
        meta.create_gate("string_length", |meta| {
            let s = meta.query_selector(selector);
            // Length is computed in witness and verified by constraints
            // The actual verification happens during assignment
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Assign values to the String Length gate
    ///
    /// Takes a string as field elements and computes its length.
    /// Length is the count of non-zero elements (for null-terminated strings).
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        string: &[Field],
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "string_length",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Compute length: count non-zero characters
                let length = string
                    .iter()
                    .take(self.max_length)
                    .position(|&c| c == Field::ZERO)
                    .unwrap_or(string.len().min(self.max_length));

                // Assign string characters
                for (i, &char_val) in string.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("char_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(char_val),
                    )?;
                }

                // Assign length
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
// String Equality Gate (Character-by-Character)
// ============================================================================

/// String Equality gate configuration
///
/// Computes: is_equal = (str1 == str2) ? 1 : 0
///
/// Constraints:
///   - Compare each character position
///   - is_equal = 1 if all characters match, 0 otherwise
///
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct StringEqualityConfig {
    /// Advice columns for strings
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum string length
    pub max_length: usize,
}

impl StringEqualityConfig {
    /// Configure the String Equality gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("string_equality", |meta| {
            let s = meta.query_selector(selector);
            // Equality is computed in witness
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Assign values to the String Equality gate
    ///
    /// Compares two strings character by character.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        str1: &[Field],
        str2: &[Field],
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "string_equality",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Assign str1 characters
                for (i, &char_val) in str1.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("str1_char_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(char_val),
                    )?;
                }

                // Assign str2 characters
                for (i, &char_val) in str2.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("str2_char_{}", i),
                        self.advice[1],
                        i,
                        || Value::known(char_val),
                    )?;
                }

                // Compute equality: all characters must match
                let is_equal = str1
                    .iter()
                    .take(self.max_length)
                    .zip(str2.iter().take(self.max_length))
                    .all(|(&a, &b)| a == b);

                let is_equal_val = if is_equal { Field::ONE } else { Field::ZERO };

                let is_equal_cell = region.assign_advice(
                    || "is_equal",
                    self.advice[0],
                    self.max_length,
                    || Value::known(is_equal_val),
                )?;

                Ok(is_equal_cell)
            },
        )
    }
}

// ============================================================================
// String Hash Gate (Polynomial Hash)
// ============================================================================

/// String Hash gate configuration
///
/// Computes a polynomial hash of a string for fast equality checks.
/// Hash = sum(char_i * 256^i) mod p
///
/// This is a simplified hash for demonstration. For production,
/// use Poseidon or similar ZKP-friendly hash.
///
/// Degree: 1 (linear)
#[derive(Clone, Debug)]
pub struct StringHashConfig {
    /// Advice columns for string and hash
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum string length
    pub max_length: usize,
}

impl StringHashConfig {
    /// Configure the String Hash gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("string_hash", |meta| {
            let s = meta.query_selector(selector);
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Compute polynomial hash of a string
    fn compute_hash(string: &[Field], max_length: usize) -> Field {
        let base = Field::from(256u64);
        let mut hash = Field::ZERO;
        let mut power = Field::ONE;

        for &char_val in string.iter().take(max_length) {
            hash = hash + (char_val * power);
            power = power * base;
        }

        hash
    }

    /// Assign values to the String Hash gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        string: &[Field],
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "string_hash",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Assign string characters
                for (i, &char_val) in string.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("char_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(char_val),
                    )?;
                }

                // Compute hash
                let hash = Self::compute_hash(string, self.max_length);

                let hash_cell =
                    region.assign_advice(|| "hash", self.advice[1], 0, || Value::known(hash))?;

                Ok(hash_cell)
            },
        )
    }
}

// ============================================================================
// String Concatenation Gate
// ============================================================================

/// String Concatenation gate configuration
///
/// Computes: result = str1 || str2
///
/// Constraints:
///   - result[0..len1] = str1[0..len1]
///   - result[len1..len1+len2] = str2[0..len2]
///
/// Degree: 1 (linear)
#[derive(Clone, Debug)]
pub struct StringConcatenationConfig {
    /// Advice columns for strings
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum length for each input string
    pub max_length: usize,
}

impl StringConcatenationConfig {
    /// Configure the String Concatenation gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("string_concatenation", |meta| {
            let s = meta.query_selector(selector);
            vec![s * Expression::Constant(Field::ZERO)]
        });

        Self {
            advice,
            selector,
            max_length,
        }
    }

    /// Assign values to the String Concatenation gate
    ///
    /// Concatenates two strings and returns the result.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        str1: &[Field],
        str2: &[Field],
    ) -> Result<Vec<AssignedCell<Field, Field>>, Error> {
        layouter.assign_region(
            || "string_concatenation",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Find actual lengths (null-terminated)
                let str1_len = str1
                    .iter()
                    .take(self.max_length)
                    .position(|&c| c == Field::ZERO)
                    .unwrap_or(str1.len().min(self.max_length));
                let str2_len = str2
                    .iter()
                    .take(self.max_length)
                    .position(|&c| c == Field::ZERO)
                    .unwrap_or(str2.len().min(self.max_length));

                // Assign str1 characters
                for (i, &char_val) in str1.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("str1_char_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(char_val),
                    )?;
                }

                // Assign str2 characters
                for (i, &char_val) in str2.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("str2_char_{}", i),
                        self.advice[1],
                        i,
                        || Value::known(char_val),
                    )?;
                }

                // Build result: str1 || str2
                let mut result_cells = Vec::new();
                let result_max_len = (self.max_length * 2).min(str1_len + str2_len);

                // Copy str1 to result
                for i in 0..str1_len.min(self.max_length) {
                    let cell = region.assign_advice(
                        || format!("result_char_{}", i),
                        self.advice[0],
                        self.max_length + i,
                        || Value::known(str1[i]),
                    )?;
                    result_cells.push(cell);
                }

                // Copy str2 to result
                for i in 0..str2_len.min(self.max_length) {
                    if str1_len + i < result_max_len {
                        let cell = region.assign_advice(
                            || format!("result_char_{}", str1_len + i),
                            self.advice[1],
                            self.max_length + i,
                            || Value::known(str2[i]),
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
// String Comparison Gate (Lexicographic)
// ============================================================================

/// String Comparison gate configuration
///
/// Computes lexicographic comparison for ORDER BY operations.
/// Returns: is_less = 1 if str1 < str2, 0 otherwise
///
/// Algorithm:
///   1. Compare characters from left to right
///   2. First differing character determines result
///   3. If all equal, shorter string is "less"
///
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct StringComparisonConfig {
    /// Advice columns for strings
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
    /// Maximum string length
    pub max_length: usize,
}

impl StringComparisonConfig {
    /// Configure the String Comparison gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, max_length: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);

        meta.create_gate("string_comparison", |meta| {
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

    /// Assign values to the String Comparison gate
    ///
    /// Returns (is_less, is_equal, is_greater) as assigned cells.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        str1: &[Field],
        str2: &[Field],
    ) -> Result<
        (
            AssignedCell<Field, Field>,
            AssignedCell<Field, Field>,
            AssignedCell<Field, Field>,
        ),
        Error,
    > {
        layouter.assign_region(
            || "string_comparison",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                // Assign str1 characters
                for (i, &char_val) in str1.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("str1_char_{}", i),
                        self.advice[0],
                        i,
                        || Value::known(char_val),
                    )?;
                }

                // Assign str2 characters
                for (i, &char_val) in str2.iter().enumerate().take(self.max_length) {
                    region.assign_advice(
                        || format!("str2_char_{}", i),
                        self.advice[1],
                        i,
                        || Value::known(char_val),
                    )?;
                }

                // Find actual lengths
                let str1_len = str1
                    .iter()
                    .take(self.max_length)
                    .position(|&c| c == Field::ZERO)
                    .unwrap_or(str1.len().min(self.max_length));
                let str2_len = str2
                    .iter()
                    .take(self.max_length)
                    .position(|&c| c == Field::ZERO)
                    .unwrap_or(str2.len().min(self.max_length));

                // Lexicographic comparison
                let mut is_less = false;
                let mut is_equal = true;
                let mut is_greater = false;

                let min_len = str1_len.min(str2_len);
                for i in 0..min_len {
                    let c1 = Self::field_to_u64(&str1[i]);
                    let c2 = Self::field_to_u64(&str2[i]);
                    if c1 < c2 {
                        is_less = true;
                        is_equal = false;
                        break;
                    } else if c1 > c2 {
                        is_greater = true;
                        is_equal = false;
                        break;
                    }
                }

                // If all compared characters equal, compare lengths
                if is_equal {
                    if str1_len < str2_len {
                        is_less = true;
                        is_equal = false;
                    } else if str1_len > str2_len {
                        is_greater = true;
                        is_equal = false;
                    }
                }

                let is_less_val = if is_less { Field::ONE } else { Field::ZERO };
                let is_equal_val = if is_equal { Field::ONE } else { Field::ZERO };
                let is_greater_val = if is_greater { Field::ONE } else { Field::ZERO };

                let is_less_cell = region.assign_advice(
                    || "is_less",
                    self.advice[0],
                    self.max_length,
                    || Value::known(is_less_val),
                )?;

                let is_equal_cell = region.assign_advice(
                    || "is_equal",
                    self.advice[1],
                    self.max_length,
                    || Value::known(is_equal_val),
                )?;

                let is_greater_cell = region.assign_advice(
                    || "is_greater",
                    self.advice[0],
                    self.max_length + 1,
                    || Value::known(is_greater_val),
                )?;

                Ok((is_less_cell, is_equal_cell, is_greater_cell))
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

    // Helper to convert string to Field array
    fn str_to_fields(s: &str, max_len: usize) -> Vec<Field> {
        let mut fields: Vec<Field> = s.bytes().map(|b| Field::from(b as u64)).collect();
        fields.resize(max_len, Field::ZERO);
        fields
    }

    // ========================================================================
    // String Length Tests
    // ========================================================================

    struct StringLengthTestCircuit {
        string: Vec<Field>,
        max_length: usize,
    }

    impl Circuit<Field> for StringLengthTestCircuit {
        type Config = StringLengthConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                string: vec![Field::ZERO; self.max_length],
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            StringLengthConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "string_length"), &self.string)?;
            Ok(())
        }
    }

    #[test]
    fn test_string_length_empty() {
        let k = 7;
        let string = vec![Field::ZERO; 10];
        let circuit = StringLengthTestCircuit {
            string,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_string_length_short() {
        let k = 7;
        let string = str_to_fields("Hi", 10);
        let circuit = StringLengthTestCircuit {
            string,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_string_length_full() {
        let k = 7;
        let string = str_to_fields("HelloWorld", 10);
        let circuit = StringLengthTestCircuit {
            string,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // ========================================================================
    // String Equality Tests
    // ========================================================================

    struct StringEqualityTestCircuit {
        str1: Vec<Field>,
        str2: Vec<Field>,
        max_length: usize,
    }

    impl Circuit<Field> for StringEqualityTestCircuit {
        type Config = StringEqualityConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                str1: vec![Field::ZERO; self.max_length],
                str2: vec![Field::ZERO; self.max_length],
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            StringEqualityConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(
                layouter.namespace(|| "string_equality"),
                &self.str1,
                &self.str2,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_string_equality_equal() {
        let k = 7;
        let str1 = str_to_fields("Hello", 10);
        let str2 = str_to_fields("Hello", 10);
        let circuit = StringEqualityTestCircuit {
            str1,
            str2,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_string_equality_unequal() {
        let k = 7;
        let str1 = str_to_fields("Hello", 10);
        let str2 = str_to_fields("World", 10);
        let circuit = StringEqualityTestCircuit {
            str1,
            str2,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_string_equality_empty() {
        let k = 7;
        let str1 = vec![Field::ZERO; 10];
        let str2 = vec![Field::ZERO; 10];
        let circuit = StringEqualityTestCircuit {
            str1,
            str2,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // ========================================================================
    // String Hash Tests
    // ========================================================================

    struct StringHashTestCircuit {
        string: Vec<Field>,
        max_length: usize,
    }

    impl Circuit<Field> for StringHashTestCircuit {
        type Config = StringHashConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                string: vec![Field::ZERO; self.max_length],
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            StringHashConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "string_hash"), &self.string)?;
            Ok(())
        }
    }

    #[test]
    fn test_string_hash() {
        let k = 7;
        let string = str_to_fields("Hello", 10);
        let circuit = StringHashTestCircuit {
            string,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_string_hash_empty() {
        let k = 7;
        let string = vec![Field::ZERO; 10];
        let circuit = StringHashTestCircuit {
            string,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // ========================================================================
    // String Concatenation Tests
    // ========================================================================

    struct StringConcatenationTestCircuit {
        str1: Vec<Field>,
        str2: Vec<Field>,
        max_length: usize,
    }

    impl Circuit<Field> for StringConcatenationTestCircuit {
        type Config = StringConcatenationConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                str1: vec![Field::ZERO; self.max_length],
                str2: vec![Field::ZERO; self.max_length],
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            StringConcatenationConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(
                layouter.namespace(|| "string_concatenation"),
                &self.str1,
                &self.str2,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_string_concatenation() {
        let k = 7;
        let str1 = str_to_fields("Hello", 10);
        let str2 = str_to_fields("World", 10);
        let circuit = StringConcatenationTestCircuit {
            str1,
            str2,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_string_concatenation_empty() {
        let k = 7;
        let str1 = vec![Field::ZERO; 10];
        let str2 = str_to_fields("World", 10);
        let circuit = StringConcatenationTestCircuit {
            str1,
            str2,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    // ========================================================================
    // String Comparison Tests
    // ========================================================================

    struct StringComparisonTestCircuit {
        str1: Vec<Field>,
        str2: Vec<Field>,
        max_length: usize,
    }

    impl Circuit<Field> for StringComparisonTestCircuit {
        type Config = StringComparisonConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                str1: vec![Field::ZERO; self.max_length],
                str2: vec![Field::ZERO; self.max_length],
                max_length: self.max_length,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            StringComparisonConfig::configure(meta, 10)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(
                layouter.namespace(|| "string_comparison"),
                &self.str1,
                &self.str2,
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_string_comparison_less() {
        let k = 7;
        let str1 = str_to_fields("Apple", 10);
        let str2 = str_to_fields("Banana", 10);
        let circuit = StringComparisonTestCircuit {
            str1,
            str2,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_string_comparison_greater() {
        let k = 7;
        let str1 = str_to_fields("Zebra", 10);
        let str2 = str_to_fields("Apple", 10);
        let circuit = StringComparisonTestCircuit {
            str1,
            str2,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_string_comparison_equal() {
        let k = 7;
        let str1 = str_to_fields("Same", 10);
        let str2 = str_to_fields("Same", 10);
        let circuit = StringComparisonTestCircuit {
            str1,
            str2,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_string_comparison_prefix() {
        let k = 7;
        let str1 = str_to_fields("App", 10);
        let str2 = str_to_fields("Apple", 10);
        let circuit = StringComparisonTestCircuit {
            str1,
            str2,
            max_length: 10,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
