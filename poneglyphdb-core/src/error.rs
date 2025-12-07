//! Error types for PoneglyphDB

use thiserror::Error;

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type
#[derive(Error, Debug)]
pub enum Error {
    #[error("Circuit error: {0}")]
    Circuit(String),

    #[error("ZKP error: {0}")]
    Zkp(String),

    #[error("Query error: {0}")]
    Query(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Witness error: {0}")]
    Witness(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),
}
