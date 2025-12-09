//! Circuit builder framework
//!
//! Provides infrastructure for building ZKP circuits.
//! Circuits are built modularly and can be composed together.

use crate::circuit::types::{Field, Wire};
use halo2::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
};

/// Circuit configuration
///
/// Stores column assignments and selectors for the circuit.
/// This config is created during circuit configuration and used during synthesis.
#[derive(Clone, Debug)]
pub struct CircuitConfig {
    /// Advice columns for witness values (private inputs)
    pub advice: [Column<Advice>; 2],
    /// Instance column for public inputs/outputs
    pub instance: Column<Instance>,
    /// Fixed column for constants
    pub fixed: Column<Fixed>,
    /// Selector for Multi-Add gate
    pub s_add: Selector,
    /// Selector for MAC (Multiply-Accumulate) gate
    pub s_mac: Selector,
    /// Selector for Multi-Multiply gate
    pub s_mul: Selector,
}

/// Circuit builder for constructing ZKP circuits
///
/// Manages wire allocation and provides utilities for circuit construction.
/// This is a helper struct for building circuits incrementally.
pub struct CircuitBuilder {
    /// Next available wire ID
    next_wire: usize,
}

impl CircuitBuilder {
    /// Create a new circuit builder
    pub fn new() -> Self {
        Self { next_wire: 0 }
    }

    /// Allocate a new wire identifier
    ///
    /// Returns a unique wire ID that can be used to reference
    /// values in the circuit.
    pub fn allocate_wire(&mut self) -> Wire {
        let wire = self.next_wire;
        self.next_wire += 1;
        wire
    }
}

impl Default for CircuitBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Base circuit implementation
///
/// Minimal circuit that can be configured and synthesized.
/// This serves as a foundation for more complex circuits.
#[derive(Default)]
pub struct BaseCircuit;

impl Circuit<Field> for BaseCircuit {
    type Config = CircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self
    }

    fn configure(meta: &mut ConstraintSystem<Field>) -> Self::Config {
        let advice = [meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        let fixed = meta.fixed_column();

        meta.enable_equality(instance);
        meta.enable_constant(fixed);
        for column in &advice {
            meta.enable_equality(*column);
        }

        let s_add = meta.selector();
        let s_mac = meta.selector();
        let s_mul = meta.selector();

        CircuitConfig {
            advice,
            instance,
            fixed,
            s_add,
            s_mac,
            s_mul,
        }
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        _layouter: impl Layouter<Field>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2::dev::MockProver;

    #[test]
    fn test_circuit_builder_creation() {
        let mut builder = CircuitBuilder::new();
        let wire = builder.allocate_wire();
        assert_eq!(wire, 0);
    }

    #[test]
    fn test_wire_allocation() {
        let mut builder = CircuitBuilder::new();
        let wire1 = builder.allocate_wire();
        let wire2 = builder.allocate_wire();
        let wire3 = builder.allocate_wire();

        assert_eq!(wire1, 0);
        assert_eq!(wire2, 1);
        assert_eq!(wire3, 2);
    }

    #[test]
    fn test_basic_circuit() {
        let circuit = BaseCircuit::default();
        let k = 4;
        let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_circuit_configuration() {
        use halo2::plonk::ConstraintSystem;

        let mut meta = ConstraintSystem::default();
        let config = BaseCircuit::configure(&mut meta);

        // Verify columns are created
        assert_eq!(config.advice.len(), 2);
    }
}
