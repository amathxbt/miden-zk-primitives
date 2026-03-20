//! # miden-zk-primitives
//!
//! Zero-knowledge cryptographic primitives for the [Miden VM](https://github.com/0xMiden/miden-vm).
//!
//! This crate provides `no_std`-compatible, educational simulations of common ZK
//! building-blocks. All group operations run in a 64-bit scalar field (wrapping
//! arithmetic), so every proof verifies in pure Rust with **zero external
//! dependencies**.
//!
//! ## Modules
//!
//! | Module | Primitive |
//! |--------|-----------|
//! | [`commitment`] | Pedersen commitment (hiding + binding) |
//! | [`merkle`] | Binary Merkle tree with membership proofs |
//! | [`nullifier`] | Spend-once nullifier (double-spend prevention) |
//! | [`range_proof`] | Bit-decomposition range proof |
//! | [`set_membership`] | Merkle-path set-membership proof |
//! | [`utils`] | Field helpers (`felt_to_bits`, `hash_two`, …) |
//! | [`elgamal`] | IND-CPA public-key encryption |
//! | [`schnorr`] | Schnorr digital signatures |
//! | [`sigma`] | Sigma protocol (proof of discrete-log knowledge) |
//! | [`accumulator`] | Multiplicative membership accumulator |
//! | [`vector_commitment`] | Position-binding vector commitment |
//! | [`zkp`] | R1CS circuit + ZK proof |
//! | [`poly_commit`] | KZG-style polynomial commitment |
//! | [`sparse_merkle`] | Sparse Merkle tree (membership + non-membership) |
//! | [`groth16`] | Groth16-style zkSNARK |
//! | [`bulletproof`] | Bulletproofs inner product argument |
//! | [`poseidon`] | Poseidon ZK-friendly hash function |
//! | [`recursive`] | Nova-style incremental verifiable computation (IVC) |
//!
//! ## Quick start
//!
//! ```rust
//! use miden_zk_primitives::{
//!     commitment::PedersenCommitment,
//!     merkle::MerkleTree,
//!     poseidon::PoseidonHash,
//! };
//!
//! // Commit to a secret value
//! let com = PedersenCommitment::commit(42, 7);
//! assert!(com.open(42, 7));
//!
//! // Build a Merkle tree and get a membership proof
//! let tree = MerkleTree::new(vec![1u64, 2, 3, 4]);
//! let proof = tree.prove(0).unwrap();
//! assert!(tree.verify(0, 1, &proof));
//!
//! // ZK-friendly hash
//! let h = PoseidonHash::hash(&[1u64, 2, 3]);
//! assert_ne!(h, 0);
//! ```
//!
//! ## Feature flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `std` | ✓ | Enables the standard `Error` trait on [`error::PrimitiveError`] |

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

// ── Original primitives ───────────────────────────────────────────────────────
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

// ── Advanced ZK features ──────────────────────────────────────────────────────
pub mod bulletproof;
pub mod groth16;
pub mod poly_commit;
pub mod poseidon;
pub mod recursive;
pub mod sparse_merkle;
pub mod zkp;
