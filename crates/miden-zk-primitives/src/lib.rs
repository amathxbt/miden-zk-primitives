//! # miden-zk-primitives
//!
//! Production-quality zero-knowledge cryptographic primitives for Miden VM.
//!
//! ## Primitives
//!
//! - [`merkle`] — Merkle membership proof helpers
//! - [`commitment`] — RPO-based commitment scheme
//! - [`range_proof`] — Range proof (prove a ≤ x ≤ b without revealing x)
//! - [`nullifier`] — Single-use nullifier construction
//! - [`set_membership`] — Set membership proof
//!
//! ## Example
//!
//! ```rust,no_run
//! use miden_zk_primitives::commitment::Commitment;
//!
//! // Commit to a secret value
//! let (commitment, opening) = Commitment::commit(42u64, rand::random());
//!
//! // Later, prove knowledge of the opening
//! let proof = opening.prove().expect("proof generation failed");
//! assert!(proof.verify(&commitment).is_ok());
//! ```

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod commitment;
pub mod merkle;
pub mod nullifier;
pub mod range_proof;
pub mod set_membership;
pub mod utils;

/// Re-export core Miden types used throughout the API.
pub use miden_core::{Felt, FieldElement, Word, ZERO};

/// Convenience result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Top-level error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The ZK proof failed to verify.
    #[error("proof verification failed: {0}")]
    VerificationFailed(String),

    /// The proof generation failed.
    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// A Merkle path is inconsistent.
    #[error("invalid merkle path: {0}")]
    InvalidMerklePath(String),

    /// A range bound was violated.
    #[error("range violation: value {value} not in [{lo}, {hi}]")]
    RangeViolation { value: u64, lo: u64, hi: u64 },

    /// Assembly compilation error.
    #[error("assembly error: {0}")]
    AssemblyError(String),

    /// Generic internal error.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}
