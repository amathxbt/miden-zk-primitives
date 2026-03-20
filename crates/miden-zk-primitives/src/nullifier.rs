//! Nullifier scheme for preventing double-spending.
//!
//! A nullifier is a deterministic, collision-resistant value derived from a
//! secret key and a note index. Publishing the nullifier reveals nothing about
//! the key, but makes it impossible to redeem the same note twice.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::nullifier::Nullifier;
//!
//! let n1 = Nullifier::derive(0xdeadbeef_u64, 0);
//! let n2 = Nullifier::derive(0xdeadbeef_u64, 1);
//! assert_ne!(n1, n2);
//! assert!(!n1.is_spent());
//! ```

use alloc::vec::Vec;

/// A spend-once token derived from a secret key and a note index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nullifier {
    /// Raw nullifier bytes.
    pub value: u64,
    spent: bool,
}

/// Domain-separated mix function.
#[inline]
fn mix(a: u64, b: u64) -> u64 {
    let x = a.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(b);
    x ^ (x >> 30)
}

impl Nullifier {
    /// Derive a nullifier from `secret_key` and `note_index`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::nullifier::Nullifier;
    /// let n = Nullifier::derive(42, 0);
    /// assert!(!n.is_spent());
    /// ```
    #[must_use]
    pub fn derive(secret_key: u64, note_index: u64) -> Self {
        let v = mix(mix(secret_key, note_index), 0xc0ffee);
        Self {
            value: v,
            spent: false,
        }
    }

    /// Returns `true` if this nullifier has been marked as spent.
    #[must_use]
    pub fn is_spent(&self) -> bool {
        self.spent
    }

    /// Mark this nullifier as spent.
    pub fn mark_spent(&mut self) {
        self.spent = true;
    }

    /// Derive a batch of nullifiers for note indices `0..count`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::nullifier::Nullifier;
    /// let batch = Nullifier::batch_derive(1, 4);
    /// assert_eq!(batch.len(), 4);
    /// ```
    #[must_use]
    pub fn batch_derive(secret_key: u64, count: usize) -> Vec<Self> {
        (0..count)
            .map(|i| Self::derive(secret_key, i as u64))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_per_index() {
        let values: Vec<u64> = (0..8).map(|i| Nullifier::derive(0xabcd, i).value).collect();
        let mut seen = alloc::collections::BTreeSet::new();
        for v in &values {
            assert!(seen.insert(v), "duplicate nullifier");
        }
    }

    #[test]
    fn spend_lifecycle() {
        let mut n = Nullifier::derive(99, 7);
        assert!(!n.is_spent());
        n.mark_spent();
        assert!(n.is_spent());
    }

    #[test]
    fn batch_derive_length() {
        let batch = Nullifier::batch_derive(1234, 16);
        assert_eq!(batch.len(), 16);
    }
}
