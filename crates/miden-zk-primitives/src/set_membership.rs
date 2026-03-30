//! Set membership — thin re-export of the accumulator-based implementation.
//!
//! Use this module when you think in terms of "is element X in set S?"
//! rather than "does element X have a valid witness for accumulator A?".

pub use crate::accumulator::{
    build_accumulator, compute_witness, element_factor, prove_membership, verify_membership,
};
