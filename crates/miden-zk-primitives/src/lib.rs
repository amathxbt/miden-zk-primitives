//! # miden-zk-primitives
//!
//! Production-quality zero-knowledge primitives built on the real
//! [Miden VM](https://github.com/0xMiden/miden-vm) (STARK-based, no trusted setup).
//!
//! ## Primitives
//!
//! | Module | Primitive | MASM instruction |
//! |--------|-----------|-----------------|
//! | [`commitment`] | Pedersen-style commitment | `hperm` |
//! | [`nullifier`]  | Double-spend nullifier    | `hperm` |
//! | [`range_proof`]| Range proof `lo ≤ v ≤ hi` | `u32gte` / `u32lte` |
//! | [`merkle`]     | Merkle membership         | `mtree_verify` |
//! | [`schnorr`]    | Schnorr-style signature   | `hperm` |
//! | [`accumulator`]| Accumulator membership    | `mul` (Goldilocks) |
//! | [`set_membership`] | Re-export of accumulator | — |
//!
//! ## Quick start
//!
//! ```toml
//! # Cargo.toml
//! [dependencies]
//! miden-zk-primitives = { git = "https://github.com/amathxbt/miden-zk-primitives" }
//! ```
//!
//! ```rust,ignore
//! use miden_zk_primitives::commitment;
//!
//! let bundle = commitment::prove_commit_open(42, /*randomness=*/ 7).unwrap();
//! commitment::verify_commit_open(42, 7, &bundle).unwrap();
//! println!("Proof size: {} bytes", bundle.proof_bytes.len());
//! ```
//!
//! ## Running the heavy proof tests
//!
//! All STARK-proof-generating tests are marked `#[ignore]` so that `cargo test`
//! finishes in seconds on any machine.  To run them locally (requires ~4 GB RAM
//! and a few minutes):
//!
//! ```bash
//! cargo test -p miden-zk-primitives -- --ignored
//! ```

pub mod accumulator;
pub mod commitment;
pub mod merkle;
pub mod nullifier;
pub mod range_proof;
pub mod schnorr;
pub mod set_membership;
pub mod utils;

pub use utils::ProofBundle;
