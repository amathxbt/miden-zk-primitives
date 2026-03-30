//! Set membership proof — thin re-export of the accumulator primitives.
//!
//! A "set" is represented by its RSA-style accumulator value.  A member
//! can prove membership by supplying their witness (the product of all
//! other members' factors) along with a STARK proof that
//! `witness × factor(element) ≡ accumulator (mod 2³²)`.

pub use crate::accumulator::{
    build_accumulator, compute_witness, prove_membership, verify_membership,
};
