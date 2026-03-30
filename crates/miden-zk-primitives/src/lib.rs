//! # miden-zk-primitives
//!
//! Production-ready zero-knowledge primitives built on the real Miden VM
//! (STARK-based, no trusted setup).
//!
//! ## Primitives
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`commitment`] | Pedersen-style commitment via RPO hash |
//! | [`nullifier`] | Nullifier to prevent double-spending |
//! | [`range_proof`] | Range proof: prove `lo ≤ value ≤ hi` |
//! | [`merkle`] | Merkle membership via `mtree_verify` |
//! | [`schnorr`] | Schnorr signature verification proof |
//! | [`accumulator`] | RSA-style accumulator membership |
//! | [`set_membership`] | Re-exports of accumulator primitives |
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use miden_zk_primitives::commitment::{prove_commit_open, verify_commit_open};
//!
//! let value = 42u64;
//! let randomness = 99u64;
//!
//! let bundle = prove_commit_open(value, randomness).expect("prove failed");
//! verify_commit_open(value, randomness, &bundle).expect("verify failed");
//! println!("Commitment proof verified ✓");
//! ```

pub mod utils;
pub mod commitment;
pub mod range_proof;
pub mod nullifier;
pub mod merkle;
pub mod schnorr;
pub mod accumulator;
pub mod set_membership;

pub use utils::ProofBundle;
