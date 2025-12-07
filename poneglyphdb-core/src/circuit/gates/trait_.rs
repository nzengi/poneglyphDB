//! CustomGate trait definition

use crate::circuit::types::Field;

/// Trait for custom gates
pub trait CustomGate {
    /// Evaluate the constraint(s) for this gate
    fn evaluate_constraint(&self, witness: &[Field]) -> Field;

    /// Get the degree of the constraint polynomial
    fn degree(&self) -> usize;
}
