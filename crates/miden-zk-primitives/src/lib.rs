//! # miden-zk-primitives
//!
//! Zero-knowledge cryptographic primitives for the [Miden VM](https://github.com/0xMiden/miden-vm).
//!
//! This crate provides educational, `no_std`-compatible simulations of common ZK
//! building-blocks. All group operations run in a 64-bit scalar field (wrapping
//! arithmetic), so every proof verifies in pure Rust with **zero external
//! dependencies beyond `rand`**.
//!
//! ## Quick start
//!
//! ```rust
//! use miden_zk_primitives::{
//!     commitment::PedersenCommitment,
//!     merkle::MerkleTree,
//! };
//!
//! // Commit to a secret value
//! let com = PedersenCommitment::commit(42, 7);
//! assert!(com.open(42, 7));
//!
//! // Build a Merkle tree and get a membership proof
//! let leaves = vec![1u64, 2, 3, 4];
//! let tree = MerkleTree::new(leaves);
//! let proof = tree.prove(0).unwrap();
//! assert!(tree.verify(0, 1, &proof));
//! ```
//!
//! ## Feature flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `std` | ✓ | Enables `std`-backed `rand` and the standard `Error` trait |

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod accumulator;
pub mod commitment;
pub mod elgamal;
pub mod error;
pub mod merkle;
pub mod nullifier;
pub mod range_proof;
pub mod schnorr;
pub mod set_membership;
pub mod sigma;
pub mod utils;
pub mod vector_commitment;
