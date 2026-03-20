//! Cryptographic accumulator over a 64-bit scalar group.
//!
//! Supports membership witnesses: each element `e` contributes factor
//! `hash(e, seed)` to the running product (wrapping multiplication).
//! A witness for element `e` is the product of all *other* factors.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::accumulator::Accumulator;
//!
//! let mut acc = Accumulator::new(0xbeef);
//! acc.add(10);
//! acc.add(20);
//! acc.add(30);
//! let witness = acc.witness(10).unwrap();
//! assert!(acc.verify_membership(10, witness));
//! ```

use alloc::vec::Vec;

/// A multiplicative accumulator.
#[derive(Debug, Clone)]
pub struct Accumulator {
    /// Seed used to derive element factors.
    seed: u64,
    elements: Vec<u64>,
}

/// Derive a prime-like factor for `element` under `seed`.
#[inline]
fn element_factor(seed: u64, element: u64) -> u64 {
    let x = element
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(seed);
    // Ensure odd (never zero) so it is invertible mod 2^64.
    (x ^ (x >> 23)) | 1
}

impl Accumulator {
    /// Create an empty accumulator with the given `seed`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::accumulator::Accumulator;
    /// let acc = Accumulator::new(1);
    /// assert_eq!(acc.value(), 1);
    /// ```
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            elements: Vec::new(),
        }
    }

    /// The current accumulator value (product of all element factors).
    #[must_use]
    pub fn value(&self) -> u64 {
        self.elements.iter().fold(1u64, |acc, &e| {
            acc.wrapping_mul(element_factor(self.seed, e))
        })
    }

    /// Add `element` to the accumulator.
    pub fn add(&mut self, element: u64) {
        self.elements.push(element);
    }

    /// Remove `element` from the accumulator (first occurrence).
    ///
    /// Returns `false` if the element was not found.
    pub fn remove(&mut self, element: u64) -> bool {
        if let Some(pos) = self.elements.iter().position(|&e| e == element) {
            self.elements.remove(pos);
            true
        } else {
            false
        }
    }

    /// Generate a membership witness for `element`.
    ///
    /// Returns `None` if `element` is not in the accumulator.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::accumulator::Accumulator;
    /// let mut acc = Accumulator::new(1);
    /// acc.add(5);
    /// acc.add(6);
    /// let w = acc.witness(5).unwrap();
    /// assert!(acc.verify_membership(5, w));
    /// ```
    #[must_use]
    pub fn witness(&self, element: u64) -> Option<u64> {
        if !self.elements.contains(&element) {
            return None;
        }
        let witness = self
            .elements
            .iter()
            .filter(|&&e| e != element)
            .fold(1u64, |acc, &e| {
                acc.wrapping_mul(element_factor(self.seed, e))
            });
        Some(witness)
    }

    /// Verify a membership witness.
    ///
    /// Checks `witness * factor(element) == accumulator_value`.
    #[must_use]
    pub fn verify_membership(&self, element: u64, witness: u64) -> bool {
        let factor = element_factor(self.seed, element);
        witness.wrapping_mul(factor) == self.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulate_and_witness() {
        let mut acc = Accumulator::new(0xbeef);
        for e in [10u64, 20, 30, 40, 50] {
            acc.add(e);
        }
        for &e in &[10u64, 20, 30, 40, 50] {
            let w = acc.witness(e).unwrap();
            assert!(acc.verify_membership(e, w), "element {e}");
        }
    }

    #[test]
    fn remove_and_verify() {
        let mut acc = Accumulator::new(1);
        acc.add(1);
        acc.add(2);
        acc.add(3);
        assert!(acc.remove(2));
        // Witness for 2 should now be None
        assert!(acc.witness(2).is_none());
        // Witnesses for remaining elements still valid
        for &e in &[1u64, 3] {
            let w = acc.witness(e).unwrap();
            assert!(acc.verify_membership(e, w));
        }
    }

    #[test]
    fn nonmember_witness_is_none() {
        let acc = Accumulator::new(99);
        assert!(acc.witness(42).is_none());
    }

    #[test]
    fn tampered_witness_fails() {
        let mut acc = Accumulator::new(7);
        acc.add(5);
        acc.add(6);
        let w = acc.witness(5).unwrap();
        assert!(!acc.verify_membership(5, w.wrapping_add(1)));
    }
}
