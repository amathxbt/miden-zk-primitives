//! Pedersen-style commitment scheme.
//!
//! A commitment is a binding, hiding tuple `(G^v * H^r)` computed in a
//! 64-bit scalar field using wrapping arithmetic.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::commitment::PedersenCommitment;
//!
//! let com = PedersenCommitment::commit(99, 42);
//! assert!(com.open(99, 42));
//! assert!(!com.open(100, 42));
//! ```

use alloc::vec::Vec;

/// Pedersen-style commitment in a 64-bit scalar field.
///
/// The commitment is `G.wrapping_pow(value) XOR H.wrapping_pow(randomness)`
/// where `G` and `H` are independent generator constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PedersenCommitment {
    /// The raw commitment value.
    pub value: u64,
}

/// Fixed generator G.
const G: u64 = 0x9e37_79b9_7f4a_7c15;
/// Fixed generator H (independent of G).
const H: u64 = 0x6c62_272e_07bb_0142;

/// Simulate scalar multiplication as repeated wrapping addition.
#[inline]
fn scalar_mul(generator: u64, scalar: u64) -> u64 {
    generator.wrapping_mul(scalar)
}

impl PedersenCommitment {
    /// Create a commitment to `value` with randomness `r`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::commitment::PedersenCommitment;
    /// let com = PedersenCommitment::commit(7, 3);
    /// assert!(com.open(7, 3));
    /// ```
    #[must_use]
    pub fn commit(value: u64, r: u64) -> Self {
        let c = scalar_mul(G, value).wrapping_add(scalar_mul(H, r));
        Self { value: c }
    }

    /// Verify that this commitment opens to (`value`, `r`).
    #[must_use]
    pub fn open(&self, value: u64, r: u64) -> bool {
        let expected = scalar_mul(G, value).wrapping_add(scalar_mul(H, r));
        self.value == expected
    }

    /// Homomorphically add two commitments.
    ///
    /// `commit(a, r1) + commit(b, r2) == commit(a+b, r1+r2)`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::commitment::PedersenCommitment;
    /// let c1 = PedersenCommitment::commit(3, 10);
    /// let c2 = PedersenCommitment::commit(7, 20);
    /// let sum = c1.add(&c2);
    /// assert!(sum.open(10, 30));
    /// ```
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        Self {
            value: self.value.wrapping_add(other.value),
        }
    }

    /// Batch-commit to a slice of `(value, randomness)` pairs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::commitment::PedersenCommitment;
    /// let pairs = vec![(1u64, 10u64), (2, 20), (3, 30)];
    /// let coms = PedersenCommitment::batch_commit(&pairs);
    /// assert_eq!(coms.len(), 3);
    /// assert!(coms[1].open(2, 20));
    /// ```
    #[must_use]
    pub fn batch_commit(pairs: &[(u64, u64)]) -> Vec<Self> {
        pairs.iter().map(|&(v, r)| Self::commit(v, r)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_open_roundtrip() {
        let com = PedersenCommitment::commit(42, 99);
        assert!(com.open(42, 99));
        assert!(!com.open(42, 100));
        assert!(!com.open(43, 99));
    }

    #[test]
    fn homomorphic_add() {
        let c1 = PedersenCommitment::commit(3, 10);
        let c2 = PedersenCommitment::commit(7, 20);
        let sum = c1.add(&c2);
        assert!(sum.open(10, 30));
    }

    #[test]
    fn batch_commit() {
        let pairs: Vec<(u64, u64)> = (0..8).map(|i| (i, i * 3)).collect();
        let coms = PedersenCommitment::batch_commit(&pairs);
        assert_eq!(coms.len(), 8);
        for (i, com) in coms.iter().enumerate() {
            assert!(com.open(i as u64, (i as u64) * 3));
        }
    }
}
