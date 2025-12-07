//! Circuit types and field definitions

use halo2::pasta::Fp;

/// Finite field element type
///
/// Pasta curve scalar field Fp. All circuit operations and constraints
/// operate on this field to ensure cryptographic correctness.
pub type Field = Fp;

/// Wire identifier in the circuit
pub type Wire = usize;

/// Gate identifier
pub type GateId = usize;

/// Constraint identifier
pub type ConstraintId = usize;

#[cfg(test)]
mod tests {
    use super::Field;
    use halo2::arithmetic::Field as _;

    #[test]
    fn test_field_basic_operations() {
        let a = Field::from(5u64);
        let b = Field::from(3u64);

        assert_eq!(a + b, Field::from(8u64));
        assert_eq!(a * b, Field::from(15u64));
        assert_eq!(a - b, Field::from(2u64));
        assert_eq!(Field::ZERO, Field::from(0u64));
        assert_eq!(Field::ONE, Field::from(1u64));
    }

    #[test]
    fn test_field_modular_arithmetic() {
        let max = Field::from(u64::MAX);
        let result = max + Field::ONE;
        assert_ne!(result, Field::ZERO);
    }

    #[test]
    fn test_field_conversion() {
        let val = Field::from(42u64);
        assert_eq!(val, Field::from(42u64));

        // Test multiple conversions
        for i in 0..100 {
            let f = Field::from(i);
            assert_eq!(f, Field::from(i));
        }
    }

    #[test]
    fn test_field_inverse() {
        let a = Field::from(5u64);
        let inv_a = a.invert().unwrap();
        let product = a * inv_a;
        assert_eq!(product, Field::ONE);

        // Zero has no inverse
        assert!(Field::ZERO.invert().is_none().unwrap_u8() == 1);
    }

    #[test]
    fn test_field_boolean_operations() {
        let zero = Field::ZERO;
        let one = Field::ONE;

        // AND: a * b
        assert_eq!(zero * one, Field::ZERO);
        assert_eq!(one * one, Field::ONE);

        // OR: a + b - a * b
        assert_eq!(zero + one - (zero * one), Field::ONE);

        // NOT: 1 - a
        assert_eq!(Field::ONE - zero, Field::ONE);
        assert_eq!(Field::ONE - one, Field::ZERO);
    }

    #[test]
    fn test_field_equality_check() {
        let a = Field::from(10u64);
        let b = Field::from(10u64);
        assert_eq!(a - b, Field::ZERO);

        let c = Field::from(5u64);
        assert_ne!(a - c, Field::ZERO);
    }

    #[test]
    fn test_field_accumulation() {
        let values = vec![
            Field::from(1u64),
            Field::from(2u64),
            Field::from(3u64),
            Field::from(4u64),
        ];

        let sum: Field = values.iter().copied().sum();
        assert_eq!(sum, Field::from(10u64));
    }

    #[test]
    fn test_field_division() {
        let a = Field::from(15u64);
        let b = Field::from(3u64);
        let quotient = a * b.invert().unwrap();
        assert_eq!(quotient, Field::from(5u64));
    }
}
