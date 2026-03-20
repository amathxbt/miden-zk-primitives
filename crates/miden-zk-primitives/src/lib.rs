//! # miden-zk-primitives
//!
//! **Production-ready** zero-knowledge primitives built directly on the
//! [Miden VM](https://github.com/0xMiden/miden-vm) — a STARK-based virtual
//! machine written in Rust.
//!
//! Every function in this crate compiles real Miden Assembly (MASM), executes
//! it through the Miden processor, and generates a genuine STARK proof that
//! anyone can verify without re-executing the program.
//!
//! ## What makes this *real*
//!
//! - Uses [`miden_vm::prove`] / [`miden_vm::verify`] — actual STARK proofs.
//! - Uses [`miden_vm::math::Felt`] — the real 64-bit Goldilocks field element.
//! - Uses [`miden_vm::StackInputs`] — real VM stack initialisation.
//! - Proof bytes are returned so callers can store / transmit / verify them.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use miden_zk_primitives::commitment;
//!
//! // Prove: commitment to value=42 with randomness=7 opens correctly.
//! let proof = commitment::prove_commit_open(42, 7).unwrap();
//! assert!(commitment::verify_commit_open(42, 7, &proof).is_ok());
//! ```

pub mod accumulator;
pub mod commitment;
pub mod merkle;
pub mod nullifier;
pub mod range_proof;
pub mod schnorr;
pub mod set_membership;
pub mod utils;
