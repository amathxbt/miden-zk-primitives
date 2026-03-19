//! Nullifier derivation for double-spend and double-vote prevention.
//!
//! A nullifier is a deterministic, collision-resistant tag derived from a
//! secret value. Submitting the same nullifier twice signals a replay.

/// A nullifier tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nullifier(u64);

impl Nullifier {
    /// Derive a nullifier from a `secret` and a domain-separation `index`.
    ///
    /// # Example
    ///
    /// ```
    /// use miden_zk_primitives::nullifier::Nullifier;
    /// let n1 = Nullifier::derive(0xdead_beef, 0);
    /// let n2 = Nullifier::derive(0xdead_beef, 1);
    /// assert_ne!(n1, n2);
    /// ```
    #[must_use]
    pub fn derive(secret: u64, index: u64) -> Self {
        let v = secret
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(index.wrapping_mul(0x6c62_272e_07bb_0142))
            ^ 0xbf58_476d_1ce4_e5b9;
        Self(v)
    }

    /// Return the raw nullifier value.
    #[must_use]
    pub fn value(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        assert_eq!(Nullifier::derive(1, 0), Nullifier::derive(1, 0));
    }

    #[test]
    fn different_index_different_nullifier() {
        assert_ne!(Nullifier::derive(1, 0), Nullifier::derive(1, 1));
    }

    #[test]
    fn different_secret_different_nullifier() {
        assert_ne!(Nullifier::derive(1, 0), Nullifier::derive(2, 0));
    }
}
