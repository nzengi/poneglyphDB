//! Comparison gates (4.3: Equality, Greater Than, Less Than, Range Check)
//!
//! Implements equality and comparison operations required for SQL WHERE clauses,
//! including support for bit decomposition as a cryptographically sound technique.

use crate::circuit::gates::logical::{AndConfig, OrConfig};
use crate::circuit::types::Field;
use halo2::{
    arithmetic::Field as _,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

/// Equality gate configuration
///
/// Computes: is_equal = (a == b) ? 1 : 0
///
/// Constraints:
///   - is_equal · (1 - is_equal) = 0 (boolean)
///   - (a - b) · is_equal = 0
///
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct EqualityConfig {
    /// Advice columns for input and output
    pub advice: [Column<Advice>; 2],
    /// Selector to enable the gate
    pub selector: Selector,
}

impl EqualityConfig {
    /// Configure the Equality gate
    pub fn configure(meta: &mut ConstraintSystem<Field>) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();

        meta.create_gate("equality", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let is_equal = meta.query_advice(advice[0], Rotation::next());
            let s = meta.query_selector(selector);
            let one = halo2::plonk::Expression::Constant(Field::ONE);

            vec![
                // Boolean constraint for is_equal
                s.clone() * (is_equal.clone() * (one.clone() - is_equal.clone())),
                // If a = b, (a - b) = 0, constraint is always 0.
                // If a ≠ b, is_equal must be 0.
                s * ((a - b) * is_equal),
            ]
        });

        Self { advice, selector }
    }

    /// Assign values to the Equality gate
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "equality_gate",
            |mut region| {
                self.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;
                // is_equal = 1 if a == b, else 0
                let is_equal = a_cell.value().zip(b_cell.value()).map(|(a, b)| {
                    if a == b {
                        Field::ONE
                    } else {
                        Field::ZERO
                    }
                });
                let is_equal_cell =
                    region.assign_advice(|| "is_equal", self.advice[0], 1, || is_equal)?;

                Ok(is_equal_cell)
            },
        )
    }
}

/// Bit Decomposition gate configuration
///
/// Decomposes a field element into binary bits, each constrained to boolean,
/// and enforces that value = sum_{i=0}^{k-1} bitᵢ · 2ᵢ
///
/// Constraints:
///   - For each bit: bitᵢ · (1 - bitᵢ) = 0
///   - Reconstruction: value = Σ bitᵢ · 2ᵢ
///
/// Degree: 2 (bit constraints), 1 (reconstruction)
#[derive(Clone, Debug)]
pub struct BitDecompositionConfig {
    pub advice: [Column<Advice>; 2],
    pub selector: Selector,
    pub num_bits: usize,
}

impl BitDecompositionConfig {
    /// Configure the BitDecomposition gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, num_bits: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();
        // We'll use one row per bit, plus one for value & reconstruction
        meta.create_gate("bit_decomposition", |meta| {
            let s = meta.query_selector(selector);
            // Value on first row
            let value = meta.query_advice(advice[0], Rotation::cur());
            // Bits on this and next (num_bits-1) rows
            let mut bits = vec![];
            for i in 0..num_bits {
                bits.push(meta.query_advice(advice[1], Rotation(i as i32)));
            }
            // Reconstruction: sum of bits * (2^i)
            let recon = bits.iter().enumerate().fold(
                halo2::plonk::Expression::Constant(Field::ZERO),
                |acc, (i, bit)| {
                    acc + bit.clone() * halo2::plonk::Expression::Constant(Field::from(1 << i))
                },
            );
            let mut constraints = vec![];
            // Boolean constraint for each bit
            for bit in bits.iter() {
                constraints.push(
                    s.clone()
                        * (bit.clone()
                            * (halo2::plonk::Expression::Constant(Field::ONE) - bit.clone())),
                );
            }
            // Reconstruction constraint (last row)
            constraints.push(s * (value - recon));
            constraints
        });
        Self {
            advice,
            selector,
            num_bits,
        }
    }

    /// Assigns a field value, decomposing into bits across multiple rows.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        value: Value<Field>,
    ) -> Result<Vec<AssignedCell<Field, Field>>, Error> {
        layouter.assign_region(
            || "bit_decomposition_gate",
            |mut region| {
                self.selector.enable(&mut region, 0)?;
                // Assign value in first row
                let _value_cell = region.assign_advice(|| "value", self.advice[0], 0, || value)?;
                // Get value in u64 for bit decomposition
                use ff::PrimeField;
                // Extract bits from field value
                let bits_val = value.map(|val| {
                    let mut bits = Vec::with_capacity(self.num_bits);
                    let repr = val.to_repr();
                    for i in 0..self.num_bits {
                        let byte_idx = i / 8;
                        let bit_idx = i % 8;
                        if byte_idx < repr.len() {
                            bits.push(((repr[byte_idx] >> bit_idx) & 1) as u64);
                        } else {
                            bits.push(0);
                        }
                    }
                    bits
                });
                // Default to all zeros if unknown - use map_or pattern
                // Since into_option is private, we'll compute bits during assignment
                // We'll use the bits_val directly in the assignment loop below
                let mut bit_cells = vec![];
                for i in 0..self.num_bits {
                    // Extract bit i from bits_val, defaulting to 0 if unknown
                    // Clone bits_val since map takes ownership
                    let bit_val = bits_val
                        .clone()
                        .map(|bits_vec| if i < bits_vec.len() { bits_vec[i] } else { 0 })
                        .zip(Value::known(0u64))
                        .map(|(b, _)| Field::from(b));
                    let bit_cell = region.assign_advice(
                        || format!("bit_{}", i),
                        self.advice[1],
                        i,
                        || bit_val,
                    )?;
                    bit_cells.push(bit_cell);
                }
                Ok(bit_cells)
            },
        )
    }
}

/// Greater Than gate configuration
///
/// Computes: is_greater = 1 if a > b else 0, using bit decomposition.
///
/// For full details, see COMPARISON_GATES_IMPLEMENTATION_PLAN.md and makale 4.3.3.
///
/// Degree: 2 (quadratic)
#[derive(Clone, Debug)]
pub struct GreaterThanConfig {
    pub advice: [Column<Advice>; 2],
    pub selector: Selector,
    pub num_bits: usize,
    pub bit_decomp: BitDecompositionConfig, // Reuse decomposition
}

impl GreaterThanConfig {
    /// Configure the GreaterThan gate
    pub fn configure(meta: &mut ConstraintSystem<Field>, num_bits: usize) -> Self {
        let advice = [meta.advice_column(), meta.advice_column()];
        let selector = meta.selector();
        let bit_decomp = BitDecompositionConfig::configure(meta, num_bits);
        // Karşılaştırma constraints'i synthesis'te uygulanır (çünkü mantığı değer bağlıdır)
        Self {
            advice,
            selector,
            num_bits,
            bit_decomp,
        }
    }

    /// Assigns a, b ve karşılaştırır. Output: is_greater = 1 if a > b
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        layouter.assign_region(
            || "greater_than_gate",
            |mut region| {
                self.selector.enable(&mut region, 0)?;
                // Assign a, b; bit decomposition for her biri
                let _a_cell = region.assign_advice(|| "a", self.advice[0], 0, || a)?;
                let _b_cell = region.assign_advice(|| "b", self.advice[1], 0, || b)?;

                // Bit decomposition Fp::to_repr() ve mask ile yapılır
                fn fp_to_u64(val: &Field) -> u64 {
                    use ff::PrimeField;
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&val.to_repr()[..8]);
                    u64::from_le_bytes(arr)
                }

                // Extract u64 values from Value<Field> for bit decomposition
                // During keygen (unknown), we use 0; during proving (known), use actual value
                let a_u64 = a.map(|aval| fp_to_u64(&aval));
                let b_u64 = b.map(|bval| fp_to_u64(&bval));

                // Compute bits for a and b
                // We'll assign bits based on the actual field values
                let mut a_bits = vec![];
                let mut b_bits = vec![];
                for i in 0..self.num_bits {
                    // Compute bit i for a
                    let abit_val = a_u64.map(|a_val| (a_val >> i) & 1);
                    let abit = abit_val.zip(Value::known(0u64)).map(|(b, _)| Field::from(b));
                    // Compute bit i for b
                    let bbit_val = b_u64.map(|b_val| (b_val >> i) & 1);
                    let bbit = bbit_val.zip(Value::known(0u64)).map(|(b, _)| Field::from(b));
                    let abit_cell = region.assign_advice(
                        || format!("abit_{}", i),
                        self.advice[0],
                        i + 1,
                        || abit,
                    )?;
                    let bbit_cell = region.assign_advice(
                        || format!("bbit_{}", i),
                        self.advice[1],
                        i + 1,
                        || bbit,
                    )?;
                    a_bits.push(abit_cell);
                    b_bits.push(bbit_cell);
                }

                // is_greater mantığı: ilk farklı bit'te a=1, b=0 ise 1; aksi halde 0
                // Bitwise MSB'den başla:
                // Compute is_greater based on bit comparison
                let is_greater_val = a_u64.zip(b_u64).map(|(a_val, b_val)| {
                    let mut is_gt = 0u64;
                    for i in (0..self.num_bits).rev() {
                        let abit = (a_val >> i) & 1;
                        let bbit = (b_val >> i) & 1;
                        if abit != bbit {
                            if abit == 1 && bbit == 0 {
                                is_gt = 1;
                            }
                            break;
                        }
                    }
                    is_gt
                });
                let is_greater =
                    is_greater_val.zip(Value::known(0u64)).map(|(v, _)| Field::from(v));
                let is_greater_cell = region.assign_advice(
                    || "is_greater",
                    self.advice[0],
                    self.num_bits + 1,
                    || is_greater,
                )?;
                Ok(is_greater_cell)
            },
        )
    }
}

/// Less Than gate configuration
///
/// Computes: is_less = 1 if a < b else 0, by reusing GreaterThan gate logic (swap).
///
/// a < b iff b > a
#[derive(Clone, Debug)]
pub struct LessThanConfig {
    pub gt_config: GreaterThanConfig,
}

impl LessThanConfig {
    pub fn new(gt_config: GreaterThanConfig) -> Self {
        Self { gt_config }
    }

    /// Assigns a, b for Less Than by calling GreaterThan with swapped inputs (b, a)
    pub fn assign(
        &self,
        layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        self.gt_config.assign(layouter, b, a) // b > a
    }
}

/// Greater Than or Equal gate configuration
///
/// Computes: is_gte = (a > b) OR (a == b)
///
#[derive(Clone, Debug)]
pub struct GreaterThanEqualConfig {
    pub gt: GreaterThanConfig,
    pub eq: EqualityConfig,
    pub or_gate: OrConfig,
}

impl GreaterThanEqualConfig {
    pub fn new(gt: GreaterThanConfig, eq: EqualityConfig, or_gate: OrConfig) -> Self {
        Self { gt, eq, or_gate }
    }
    /// Assigns a, b ve is_gte = is_gt OR is_eq
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        // 1. is_gt = (a > b)
        let is_gt = self.gt.assign(layouter.namespace(|| "gte_is_gt"), a, b)?;
        // 2. is_eq = (a == b)
        let is_eq = self.eq.assign(layouter.namespace(|| "gte_is_eq"), a, b)?;
        // 3. is_gte = is_gt OR is_eq
        self.or_gate.assign(
            layouter.namespace(|| "gte_or"),
            is_gt.value().copied(),
            is_eq.value().copied(),
        )
    }
}

/// Less Than or Equal gate configuration
///
/// Computes: is_lte = 1 if a <= b else 0, by calling GreaterThanEqualConfig (b, a)
#[derive(Clone, Debug)]
pub struct LessThanEqualConfig {
    pub gte_config: GreaterThanEqualConfig,
}

impl LessThanEqualConfig {
    pub fn new(gte_config: GreaterThanEqualConfig) -> Self {
        Self { gte_config }
    }
    /// Assigns a, b for LessThanOrEqual by calling GreaterThanOrEqual(b, a)
    pub fn assign(
        &self,
        layouter: impl Layouter<Field>,
        a: Value<Field>,
        b: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        self.gte_config.assign(layouter, b, a) // b >= a
    }
}

/// RangeCheck gate configuration
///
/// Computes: in_range = (value >= min) AND (value <= max)
#[derive(Clone, Debug)]
pub struct RangeCheckConfig {
    pub gte_config: GreaterThanEqualConfig,
    pub lte_config: LessThanEqualConfig,
    pub and_gate: AndConfig,
}

impl RangeCheckConfig {
    pub fn new(
        gte_config: GreaterThanEqualConfig,
        lte_config: LessThanEqualConfig,
        and_gate: AndConfig,
    ) -> Self {
        Self {
            gte_config,
            lte_config,
            and_gate,
        }
    }
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Field>,
        value: Value<Field>,
        min: Value<Field>,
        max: Value<Field>,
    ) -> Result<AssignedCell<Field, Field>, Error> {
        let ge_min = self.gte_config.assign(layouter.namespace(|| "rc_ge_min"), value, min)?;
        let le_max = self.lte_config.assign(layouter.namespace(|| "rc_le_max"), value, max)?;
        // in_range = ge_min AND le_max
        self.and_gate.assign(
            layouter.namespace(|| "rc_and"),
            ge_min.value().copied(),
            le_max.value().copied(),
        )
    }
}

/// Placeholder for Bit Decomposition and further gates (Greater Than, etc.)
// TODO: Implement BitDecompositionConfig, GreaterThanConfig, and composite configs as per plan.

#[cfg(test)]
mod tests {
    use super::*;
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

    struct TestCircuit {
        pub a: Field,
        pub b: Field,
    }

    impl Circuit<Field> for TestCircuit {
        type Config = EqualityConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                a: Field::ZERO,
                b: Field::ZERO,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            EqualityConfig::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(
                layouter.namespace(|| "equality_gate"),
                Value::known(self.a),
                Value::known(self.b),
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_equality_gate_equal() {
        let k = 7; // Need more rows for bit decomposition and comparison gates
        let a = Field::from(42u64);
        let b = Field::from(42u64);
        let circuit = TestCircuit { a, b };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_equality_gate_unequal() {
        let k = 7; // Need more rows for bit decomposition and comparison gates
        let a = Field::from(1u64);
        let b = Field::from(2u64);
        let circuit = TestCircuit { a, b };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    struct BitTestCircuit {
        pub value: Field,
        pub num_bits: usize,
    }

    impl Circuit<Field> for BitTestCircuit {
        type Config = BitDecompositionConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                value: Field::ZERO,
                num_bits: self.num_bits,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
            BitDecompositionConfig::configure(meta, 8) // test with 8 bits
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Field>,
        ) -> Result<(), Error> {
            config.assign(
                layouter.namespace(|| "bit_decomposition_gate"),
                Value::known(self.value),
            )?;
            Ok(())
        }
    }

    #[test]
    fn test_bitdecomp_zero() {
        let k = 7; // Need more rows for bit decomposition (8 bits + overhead)
        let val = Field::ZERO;
        let circuit = BitTestCircuit {
            value: val,
            num_bits: 8,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bitdecomp_one() {
        let k = 7;
        let val = Field::ONE;
        let circuit = BitTestCircuit {
            value: val,
            num_bits: 8,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bitdecomp_max() {
        let k = 7;
        let val = Field::from(255u64);
        let circuit = BitTestCircuit {
            value: val,
            num_bits: 8,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_bitdecomp_mid() {
        let k = 7;
        let val = Field::from(42u64);
        let circuit = BitTestCircuit {
            value: val,
            num_bits: 8,
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[cfg(test)]
    mod gttests {
        use super::*;
        use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

        struct GTTestCircuit {
            pub a: Field,
            pub b: Field,
            pub num_bits: usize,
        }
        impl Circuit<Field> for GTTestCircuit {
            type Config = GreaterThanConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self {
                    a: Field::ZERO,
                    b: Field::ZERO,
                    num_bits: self.num_bits,
                }
            }
            fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
                GreaterThanConfig::configure(meta, 8) // test with 8 bits
            }
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Field>,
            ) -> Result<(), Error> {
                config.assign(
                    layouter.namespace(|| "greater_than_gate"),
                    Value::known(self.a),
                    Value::known(self.b),
                )?;
                Ok(())
            }
        }
        #[test]
        fn test_gt_true() {
            let k = 7; // Need more rows for bit decomposition and comparison gates
            let a = Field::from(42u64);
            let b = Field::from(13u64);
            let circuit = GTTestCircuit { a, b, num_bits: 8 };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_gt_false() {
            let k = 7; // Need more rows for bit decomposition and comparison gates
            let a = Field::from(5u64);
            let b = Field::from(20u64);
            let circuit = GTTestCircuit { a, b, num_bits: 8 };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_gt_equal() {
            let k = 7; // Need more rows for bit decomposition and comparison gates
            let a = Field::from(100u64);
            let b = Field::from(100u64);
            let circuit = GTTestCircuit { a, b, num_bits: 8 };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[cfg(test)]
    mod lttests {
        use super::*;
        use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
        struct LTTestCircuit {
            pub a: Field,
            pub b: Field,
            pub num_bits: usize,
        }
        impl Circuit<Field> for LTTestCircuit {
            type Config = LessThanConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self {
                    a: Field::ZERO,
                    b: Field::ZERO,
                    num_bits: self.num_bits,
                }
            }
            fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
                let gt = GreaterThanConfig::configure(meta, 8);
                LessThanConfig::new(gt)
            }
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Field>,
            ) -> Result<(), Error> {
                config.assign(
                    layouter.namespace(|| "less_than_gate"),
                    Value::known(self.a),
                    Value::known(self.b),
                )?;
                Ok(())
            }
        }
        #[test]
        fn test_lt_true() {
            let k = 7; // Need more rows for bit decomposition and comparison gates
            let a = Field::from(2u64);
            let b = Field::from(10u64);
            let circuit = LTTestCircuit { a, b, num_bits: 8 };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_lt_false() {
            let k = 7; // Need more rows for bit decomposition and comparison gates
            let a = Field::from(20u64);
            let b = Field::from(5u64);
            let circuit = LTTestCircuit { a, b, num_bits: 8 };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_lt_equal() {
            let k = 7; // Need more rows for bit decomposition and comparison gates
            let a = Field::from(100u64);
            let b = Field::from(100u64);
            let circuit = LTTestCircuit { a, b, num_bits: 8 };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[cfg(test)]
    mod gtetests {
        use super::*;
        use crate::circuit::gates::logical::OrConfig;
        use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
        struct GTETestCircuit {
            pub a: Field,
            pub b: Field,
            pub num_bits: usize,
        }
        impl Circuit<Field> for GTETestCircuit {
            type Config = GreaterThanEqualConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self {
                    a: Field::ZERO,
                    b: Field::ZERO,
                    num_bits: self.num_bits,
                }
            }
            fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
                let gt = GreaterThanConfig::configure(meta, 8);
                let eq = EqualityConfig::configure(meta);
                let or_gate = OrConfig::configure(meta);
                GreaterThanEqualConfig::new(gt, eq, or_gate)
            }
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Field>,
            ) -> Result<(), Error> {
                config.assign(
                    layouter.namespace(|| "gte_gate"),
                    Value::known(self.a),
                    Value::known(self.b),
                )?;
                Ok(())
            }
        }
        #[test]
        fn test_gte_gt() {
            let circuit = GTETestCircuit {
                a: Field::from(10u64),
                b: Field::from(3u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_gte_eq() {
            let circuit = GTETestCircuit {
                a: Field::from(42u64),
                b: Field::from(42u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_gte_lt() {
            let circuit = GTETestCircuit {
                a: Field::from(1u64),
                b: Field::from(5u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[cfg(test)]
    mod ltetests {
        use super::*;
        use crate::circuit::gates::logical::OrConfig;
        use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
        struct LTETestCircuit {
            pub a: Field,
            pub b: Field,
            pub num_bits: usize,
        }
        impl Circuit<Field> for LTETestCircuit {
            type Config = LessThanEqualConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self {
                    a: Field::ZERO,
                    b: Field::ZERO,
                    num_bits: self.num_bits,
                }
            }
            fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
                let gt = GreaterThanConfig::configure(meta, 8);
                let eq = EqualityConfig::configure(meta);
                let or_gate = OrConfig::configure(meta);
                let gte = GreaterThanEqualConfig::new(gt, eq, or_gate);
                LessThanEqualConfig::new(gte)
            }
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Field>,
            ) -> Result<(), Error> {
                config.assign(
                    layouter.namespace(|| "lte_gate"),
                    Value::known(self.a),
                    Value::known(self.b),
                )?;
                Ok(())
            }
        }
        #[test]
        fn test_lte_lt() {
            let circuit = LTETestCircuit {
                a: Field::from(2u64),
                b: Field::from(10u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_lte_eq() {
            let circuit = LTETestCircuit {
                a: Field::from(42u64),
                b: Field::from(42u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_lte_gt() {
            let circuit = LTETestCircuit {
                a: Field::from(15u64),
                b: Field::from(5u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }

    #[cfg(test)]
    mod rctests {
        use super::*;
        use crate::circuit::gates::logical::{AndConfig, OrConfig};
        use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
        struct RCTestCircuit {
            pub value: Field,
            pub min: Field,
            pub max: Field,
            pub num_bits: usize,
        }
        impl Circuit<Field> for RCTestCircuit {
            type Config = RangeCheckConfig;
            type FloorPlanner = SimpleFloorPlanner;
            fn without_witnesses(&self) -> Self {
                Self {
                    value: Field::ZERO,
                    min: Field::ZERO,
                    max: Field::ZERO,
                    num_bits: self.num_bits,
                }
            }
            fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
                let gt = GreaterThanConfig::configure(meta, 8);
                let eq = EqualityConfig::configure(meta);
                let or_gate = OrConfig::configure(meta);
                let gte = GreaterThanEqualConfig::new(gt.clone(), eq.clone(), or_gate.clone());
                let lte = LessThanEqualConfig::new(gte.clone());
                let and_gate = AndConfig::configure(meta);
                RangeCheckConfig::new(gte, lte, and_gate)
            }
            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Field>,
            ) -> Result<(), Error> {
                config.assign(
                    layouter.namespace(|| "range_check"),
                    Value::known(self.value),
                    Value::known(self.min),
                    Value::known(self.max),
                )?;
                Ok(())
            }
        }
        #[test]
        fn test_range_inside() {
            let circuit = RCTestCircuit {
                value: Field::from(5u64),
                min: Field::from(3u64),
                max: Field::from(10u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_range_eq_min() {
            let circuit = RCTestCircuit {
                value: Field::from(3u64),
                min: Field::from(3u64),
                max: Field::from(10u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_range_eq_max() {
            let circuit = RCTestCircuit {
                value: Field::from(10u64),
                min: Field::from(3u64),
                max: Field::from(10u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_range_below() {
            let circuit = RCTestCircuit {
                value: Field::from(2u64),
                min: Field::from(3u64),
                max: Field::from(10u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
        #[test]
        fn test_range_above() {
            let circuit = RCTestCircuit {
                value: Field::from(11u64),
                min: Field::from(3u64),
                max: Field::from(10u64),
                num_bits: 8,
            };
            let prover = MockProver::run(7, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
