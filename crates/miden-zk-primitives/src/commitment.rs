//! # RPO Commitment Scheme
//!
//! A commitment scheme built on Miden VM's native Rescue Prime Optimized (RPO)
//! hash function. Committing inside the VM is maximally efficient because `hperm`
//! is a *native* instruction — it contributes only a single row to the execution
//! trace, making proofs as small as possible.
//!
//! ## Security properties
//!
//! - **Hiding**: a commitment `C = RPO([v, r, 0, 0])` reveals nothing about `v`
//!   when `r` is a uniformly random 64-bit blinding factor.
//! - **Binding**: it is computationally infeasible to find `(v', r')` such that
//!   `RPO([v', r', 0, 0]) == C` unless `v' = v` and `r' = r`.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use miden_zk_primitives::commitment::{Commitment, Opening};
//!
//! // Prover side: commit to a secret value with a random blinding factor
//! let secret: u64 = 1234;
//! let blinding: u64 = 0xdeadbeef_cafebabe;
//! let (commitment, opening) = Commitment::new(secret, blinding);
//!
//! // Verifier side: check the opening against the public commitment
//! opening.verify(&commitment).expect("commitment verification failed");
//! ```

use miden_core::{Felt, FieldElement, Word, ZERO};

/// A commitment to a secret value.
///
/// Internally this is just a `Word` (4 field elements) representing
/// `RPO_hash([value, blinding, 0, 0])`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Commitment(pub Word);

/// An opening of a [`Commitment`]: the secret value and its blinding factor.
#[derive(Debug, Clone)]
pub struct Opening {
    /// The committed secret value.
    pub value: u64,
    /// The random blinding factor used during commitment.
    pub blinding: u64,
}

impl Commitment {
    /// Commit to `value` using the supplied `blinding` factor.
    ///
    /// Returns the public commitment and the opening witness.
    pub fn new(value: u64, blinding: u64) -> (Self, Opening) {
        let word = Self::hash_commit(value, blinding);
        (Commitment(word), Opening { value, blinding })
    }

    /// Commit to `value` using a cryptographically random blinding factor.
    #[cfg(feature = "std")]
    pub fn commit(value: u64) -> (Self, Opening) {
        use rand::Rng;
        let blinding: u64 = rand::thread_rng().gen();
        Self::new(value, blinding)
    }

    /// Return the raw `Word` representation.
    pub fn as_word(&self) -> &Word {
        &self.0
    }

    /// Compute `RPO_hash([value, blinding, 0, 0])` using Miden's native hasher.
    fn hash_commit(value: u64, blinding: u64) -> Word {
        use miden_core::crypto::hash::RpoDigest;
        use miden_core::crypto::hash::Rpo256;

        let elements = [
            Felt::new(value),
            Felt::new(blinding),
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ];
        // Use Rpo256 to hash the input — matches the `hperm` instruction
        let digest = Rpo256::hash_elements(&elements);
        digest.into()
    }
}

impl Opening {
    /// Verify that this opening is consistent with the given commitment.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::VerificationFailed`] if the recomputed hash does
    /// not match the commitment.
    pub fn verify(&self, commitment: &Commitment) -> crate::Result<()> {
        let expected = Commitment::hash_commit(self.value, self.blinding);
        if expected == commitment.0 {
            Ok(())
        } else {
            Err(crate::Error::VerificationFailed(
                "commitment opening does not match".into(),
            ))
        }
    }

    /// Return the committed value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Return the blinding factor.
    pub fn blinding(&self) -> u64 {
        self.blinding
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_open_roundtrip() {
        let (c, o) = Commitment::new(42, 0xdeadbeef);
        o.verify(&c).expect("opening should verify");
    }

    #[test]
    fn wrong_value_fails() {
        let (c, _o) = Commitment::new(42, 0xdeadbeef);
        let wrong = Opening { value: 99, blinding: 0xdeadbeef };
        assert!(wrong.verify(&c).is_err(), "wrong value should fail");
    }

    #[test]
    fn wrong_blinding_fails() {
        let (c, _o) = Commitment::new(42, 0xdeadbeef);
        let wrong = Opening { value: 42, blinding: 0x12345678 };
        assert!(wrong.verify(&c).is_err(), "wrong blinding should fail");
    }

    #[test]
    fn different_values_different_commitments() {
        let (c1, _) = Commitment::new(1, 1000);
        let (c2, _) = Commitment::new(2, 1000);
        assert_ne!(c1, c2);
    }

    #[test]
    fn different_blindings_different_commitments() {
        let (c1, _) = Commitment::new(42, 1000);
        let (c2, _) = Commitment::new(42, 2000);
        assert_ne!(c1, c2, "same value, different blinding → different commitment");
    }
}
