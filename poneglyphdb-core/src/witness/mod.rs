//! Witness computation (Makale 3.3.2)

pub mod computer;
pub mod extractor;
pub mod optimizer;
pub mod types;

pub use computer::WitnessComputer;
pub use extractor::WitnessExtractor;
