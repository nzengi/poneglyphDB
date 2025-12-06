//! PoneglyphDB Core Library
//!
//! Efficient Non-interactive Zero-Knowledge Proofs for Arbitrary SQL-Query Verification

pub mod circuit;
pub mod database;
pub mod error;
pub mod query;
pub mod witness;
pub mod zkp;

pub use error::{Error, Result};

