//! CustomGate trait definition
//!
//! Provides a common interface for all custom gates in PoneglyphDB.
//! This trait enables:
//! - Gate metadata querying (degree, name, constraints)
//! - Constraint evaluation for testing and validation
//! - Generic gate composition and analysis
//!
//! Note: Gates in PoneglyphDB use Halo2's Config pattern with `configure()` and `assign()` methods.
//! This trait provides additional metadata and testing capabilities.

use crate::circuit::types::Field;

/// Trait for custom gates in PoneglyphDB
///
/// All custom gates should implement this trait to provide:
/// - Constraint evaluation for testing
/// - Gate degree information
/// - Gate metadata (name, description)
///
/// This trait is primarily used for:
/// - Testing and validation
/// - Gate analysis and optimization
/// - Documentation generation
pub trait CustomGate {
    /// Get the name of the gate
    fn name(&self) -> &'static str;

    /// Get the description of the gate
    fn description(&self) -> &'static str;

    /// Get the degree of the constraint polynomial
    ///
    /// The degree determines the complexity of the constraint:
    /// - Degree 1: Linear constraints (e.g., addition)
    /// - Degree 2: Quadratic constraints (e.g., multiplication, boolean)
    /// - Degree 3+: Higher-degree constraints (e.g., S-box operations)
    fn degree(&self) -> usize;

    /// Evaluate the constraint(s) for this gate given witness values
    ///
    /// This method is used for testing and validation.
    /// It evaluates the gate's constraint(s) with the provided witness values
    /// and returns the constraint evaluation result.
    ///
    /// For a valid witness assignment, this should return `Field::ZERO`.
    ///
    /// # Arguments
    /// * `witness` - Slice of field elements representing the witness values
    ///   The order and meaning of values depends on the specific gate implementation.
    ///
    /// # Returns
    /// The constraint evaluation result. Should be `Field::ZERO` for valid assignments.
    fn evaluate_constraint(&self, witness: &[Field]) -> Field;

    /// Get the number of input values required by this gate
    fn num_inputs(&self) -> usize;

    /// Get the number of output values produced by this gate
    fn num_outputs(&self) -> usize;

    /// Check if the gate is a composition of other gates
    ///
    /// Returns `true` if this gate is composed of other gates (e.g., GreaterThanEqual
    /// is composed of GreaterThan + Equality + OR).
    fn is_composite(&self) -> bool {
        false
    }

    /// Get the gate category
    ///
    /// Categories: "arithmetic", "logical", "comparison", "string", "array", "special"
    fn category(&self) -> &'static str;
}

/// Helper trait for gates that can be validated
///
/// This trait provides validation methods for gates.
pub trait GateValidation: CustomGate {
    /// Validate that the witness values satisfy the gate constraints
    ///
    /// Returns `true` if the witness values are valid, `false` otherwise.
    fn validate_witness(&self, witness: &[Field]) -> bool {
        use halo2::arithmetic::Field as _;
        self.evaluate_constraint(witness) == Field::zero()
    }

    /// Get constraint description as a string
    ///
    /// Returns a human-readable description of the constraint(s).
    fn constraint_description(&self) -> String {
        format!(
            "{}: {} (degree: {})",
            self.name(),
            self.description(),
            self.degree()
        )
    }
}

// Blanket implementation: All CustomGate implement GateValidation
impl<T: CustomGate> GateValidation for T {}

/// Gate metadata for analysis and documentation
#[derive(Clone, Debug)]
pub struct GateMetadata {
    /// Gate name
    pub name: &'static str,
    /// Gate description
    pub description: &'static str,
    /// Constraint degree
    pub degree: usize,
    /// Number of inputs
    pub num_inputs: usize,
    /// Number of outputs
    pub num_outputs: usize,
    /// Gate category
    pub category: &'static str,
    /// Whether the gate is composite
    pub is_composite: bool,
}

impl<T: CustomGate> From<&T> for GateMetadata {
    fn from(gate: &T) -> Self {
        Self {
            name: gate.name(),
            description: gate.description(),
            degree: gate.degree(),
            num_inputs: gate.num_inputs(),
            num_outputs: gate.num_outputs(),
            category: gate.category(),
            is_composite: gate.is_composite(),
        }
    }
}

/// Utility functions for gate analysis
pub mod utils {
    use super::{CustomGate, GateMetadata};

    /// Collect metadata from all gates in a collection
    pub fn collect_metadata<G: CustomGate>(gates: &[G]) -> Vec<GateMetadata> {
        gates.iter().map(|g| GateMetadata::from(g)).collect()
    }

    /// Find gates by category
    pub fn gates_by_category<'a, G: CustomGate>(gates: &'a [G], category: &str) -> Vec<&'a G> {
        gates.iter().filter(|g| g.category() == category).collect()
    }

    /// Find gates by degree
    pub fn gates_by_degree<'a, G: CustomGate>(gates: &'a [G], degree: usize) -> Vec<&'a G> {
        gates.iter().filter(|g| g.degree() == degree).collect()
    }

    /// Calculate total constraint degree for a set of gates
    pub fn total_degree<G: CustomGate>(gates: &[G]) -> usize {
        gates.iter().map(|g| g.degree()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Example gate implementation for testing
    struct TestGate {
        name: &'static str,
        degree: usize,
        category: &'static str,
    }

    impl CustomGate for TestGate {
        fn name(&self) -> &'static str {
            self.name
        }

        fn description(&self) -> &'static str {
            "Test gate for trait testing"
        }

        fn degree(&self) -> usize {
            self.degree
        }

        fn evaluate_constraint(&self, witness: &[Field]) -> Field {
            use halo2::arithmetic::Field as _;
            // Simple test constraint: sum of inputs should equal first input
            if witness.len() < 2 {
                return Field::one(); // Invalid
            }
            witness[0] - witness[0] // Always zero for testing
        }

        fn num_inputs(&self) -> usize {
            2
        }

        fn num_outputs(&self) -> usize {
            1
        }

        fn category(&self) -> &'static str {
            self.category
        }
    }

    #[test]
    fn test_gate_metadata() {
        let gate = TestGate {
            name: "test_gate",
            degree: 2,
            category: "test",
        };

        let metadata = GateMetadata::from(&gate);
        assert_eq!(metadata.name, "test_gate");
        assert_eq!(metadata.degree, 2);
        assert_eq!(metadata.category, "test");
        assert_eq!(metadata.num_inputs, 2);
        assert_eq!(metadata.num_outputs, 1);
    }

    #[test]
    fn test_gate_validation() {
        let gate = TestGate {
            name: "test_gate",
            degree: 2,
            category: "test",
        };

        let witness = vec![Field::from(1u64), Field::from(2u64)];
        assert!(gate.validate_witness(&witness));
    }

    #[test]
    fn test_utils_collect_metadata() {
        let gates = vec![
            TestGate {
                name: "gate1",
                degree: 1,
                category: "arithmetic",
            },
            TestGate {
                name: "gate2",
                degree: 2,
                category: "logical",
            },
        ];

        let metadata = utils::collect_metadata(&gates);
        assert_eq!(metadata.len(), 2);
        assert_eq!(metadata[0].name, "gate1");
        assert_eq!(metadata[1].name, "gate2");
    }

    #[test]
    fn test_utils_gates_by_category() {
        let gates = vec![
            TestGate {
                name: "gate1",
                degree: 1,
                category: "arithmetic",
            },
            TestGate {
                name: "gate2",
                degree: 2,
                category: "logical",
            },
            TestGate {
                name: "gate3",
                degree: 1,
                category: "arithmetic",
            },
        ];

        let arithmetic_gates = utils::gates_by_category(&gates, "arithmetic");
        assert_eq!(arithmetic_gates.len(), 2);
    }

    #[test]
    fn test_utils_gates_by_degree() {
        let gates = vec![
            TestGate {
                name: "gate1",
                degree: 1,
                category: "arithmetic",
            },
            TestGate {
                name: "gate2",
                degree: 2,
                category: "logical",
            },
            TestGate {
                name: "gate3",
                degree: 1,
                category: "arithmetic",
            },
        ];

        let degree_1_gates = utils::gates_by_degree(&gates, 1);
        assert_eq!(degree_1_gates.len(), 2);
    }

    #[test]
    fn test_utils_total_degree() {
        let gates = vec![
            TestGate {
                name: "gate1",
                degree: 1,
                category: "arithmetic",
            },
            TestGate {
                name: "gate2",
                degree: 2,
                category: "logical",
            },
            TestGate {
                name: "gate3",
                degree: 1,
                category: "arithmetic",
            },
        ];

        let total = utils::total_degree(&gates);
        assert_eq!(total, 4); // 1 + 2 + 1
    }
}
