//! Pedersen-style commitment scheme.
//!
//! A commitment `C = H(value || randomness)` hides the value while binding
//! the committer to it. Opening reveals `(value, randomness)`.

#[cfg(feature = "std")]
use rand::Rng;

/// A commitment to a `u64` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PedersenCommitment {
    value: u64,
}

impl PedersenCommitment {
    /// Commit to `value` using a random blinding factor.
    ///
    /// Returns `(commitment, randomness)`.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "std")] {
    /// use miden_zk_primitives::commitment::PedersenCommitment;
    /// use rand::thread_rng;
    /// let (comm, r) = PedersenCommitment::commit(42, &mut thread_rng());
    /// assert!(comm.open(42, r));
    /// # }
    /// ```
    #[cfg(feature = "std")]
    pub fn commit<R: Rng>(value: u64, rng: &mut R) -> (Self, u64) {
        let randomness: u64 = rng.gen();
        let committed = Self::hash(value, randomness);
        (Self { value: committed }, randomness)
    }

    /// Open the commitment: verify that `H(value || randomness) == self`.
    ///
    /// Returns `true` if the opening is valid.
    pub fn open(&self, value: u64, randomness: u64) -> bool {
        Self::hash(value, randomness) == self.value
    }

    /// Return the raw commitment value (opaque to the verifier).
    #[must_use]
    pub fn value(&self) -> u64 {
        self.value
    }

    fn hash(value: u64, randomness: u64) -> u64 {
        value
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(randomness.wrapping_mul(0x6c62_272e_07bb_0142))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use rand::thread_rng;

    #[test]
    #[cfg(feature = "std")]
    fn commit_and_open() {
        let mut rng = thread_rng();
        let (comm, r) = PedersenCommitment::commit(42, &mut rng);
        assert!(comm.open(42, r));
        assert!(!comm.open(43, r));
    }

    #[test]
    #[cfg(feature = "std")]
    fn different_randomness_gives_different_commitment() {
        let mut rng = thread_rng();
        let (c1, _) = PedersenCommitment::commit(7, &mut rng);
        let (c2, _) = PedersenCommitment::commit(7, &mut rng);
        // With overwhelming probability the two commitments differ.
        assert_ne!(c1, c2);
    }
}
