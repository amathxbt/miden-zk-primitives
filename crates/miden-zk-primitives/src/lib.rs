//! # miden-zk-primitives
//!
//! A production-quality library of zero-knowledge primitives for the
//! [Miden VM](https://github.com/0xMiden/miden-vm) ecosystem.
//!
//! ## Modules
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`commitment`] | Pedersen-style hiding commitments |
//! | [`merkle`]     | Binary Merkle tree with proof generation & verification |
//! | [`nullifier`]  | Deterministic nullifier derivation |
//! | [`range_proof`] | Range proofs over `u64` values |
//! | [`set_membership`] | Set-membership proofs |
//! | [`utils`]      | Shared helpers |
//!
//! ## Feature Flags
//!
//! | Flag  | Default | Description |
//! |-------|---------|-------------|
//! | `std` | yes     | Enables `std`-dependent code (randomness, I/O) |
//!
//! ## Quick Start
//!
//! ```
//! # #[cfg(feature = "std")] {
//! use miden_zk_primitives::commitment::PedersenCommitment;
//! use miden_zk_primitives::merkle::MerkleTree;
//! use rand::thread_rng;
//!
//! // Commit to a secret value
//! let (comm, randomness) = PedersenCommitment::commit(42, &mut thread_rng());
//! assert!(comm.open(42, randomness));
//!
//! // Build a Merkle tree and verify a proof
//! let tree = MerkleTree::build(&[1, 2, 3, 4]);
//! let proof = tree.proof(0);
//! assert!(MerkleTree::verify(1, 0, &proof, tree.root()));
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]
#![warn(clippy::all)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod commitment;
pub mod error;
pub mod merkle;
pub mod nullifier;
pub mod range_proof;
pub mod set_membership;
pub mod utils;
