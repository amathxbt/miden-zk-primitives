//! Range proof: prove that a secret value lies in `[min, max]`.
//!
//! The proof is a simulated bit-decomposition commitment: commit to each bit
//! of `(value - min)` and verify the sum reconstructs `(value - min)`.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::range_proof::RangeProof;
//!
//! let proof = RangeProof::prove(25, 18, 120).unwrap();
//! assert!(proof.verify(18, 120));
//! assert!(!proof.verify(0, 20)); // wrong range
//! ```

use alloc::vec::Vec;

use crate::error::PrimitiveError;

/// A bit-commitment range proof.
#[derive(Debug, Clone)]
pub struct RangeProof {
    /// Commitment to each bit of `value - min`.
    pub bit_commitments: Vec<u64>,
    /// Blinding factors used per bit.
    pub randomness: Vec<u64>,
    /// The original value (kept for verification in this simulation).
    value: u64,
}

/// Pedersen-style commitment helper (same generators as `commitment.rs`).
#[inline]
fn commit(v: u64, r: u64) -> u64 {
    v.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(r.wrapping_mul(0x6c62_272e_07bb_0142))
}

impl RangeProof {
    /// Prove that `value` lies in `[min, max]`.
    ///
    /// Returns `Err` if `value` is out of range.
    ///
    /// # Errors
    ///
    /// Returns [`PrimitiveError::OutOfRange`] when `value < min` or `value > max`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::range_proof::RangeProof;
    /// let p = RangeProof::prove(50, 0, 100).unwrap();
    /// assert!(p.verify(0, 100));
    /// ```
    pub fn prove(value: u64, min: u64, max: u64) -> Result<Self, PrimitiveError> {
        if value < min || value > max {
            return Err(PrimitiveError::OutOfRange { value, min, max });
        }
        let diff = value - min;
        let mut bit_commitments = Vec::new();
        let mut randomness = Vec::new();
        for bit_pos in 0..64u32 {
            let bit = (diff >> bit_pos) & 1;
            // Use deterministic "randomness" derived from value and bit position
            let r = commit(value ^ 0xdeadbeef, u64::from(bit_pos));
            bit_commitments.push(commit(bit, r));
            randomness.push(r);
        }
        Ok(Self {
            bit_commitments,
            randomness,
            value,
        })
    }

    /// Verify this range proof against `[min, max]`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::range_proof::RangeProof;
    /// let p = RangeProof::prove(30, 18, 65).unwrap();
    /// assert!(p.verify(18, 65));
    /// ```
    #[must_use]
    pub fn verify(&self, min: u64, max: u64) -> bool {
        if self.value < min || self.value > max {
            return false;
        }
        let diff = self.value - min;
        // Reconstruct expected bit commitments and compare
        let expected: Vec<u64> = (0..64u32)
            .map(|bit_pos| {
                let bit = (diff >> bit_pos) & 1;
                let r = commit(self.value ^ 0xdeadbeef, u64::from(bit_pos));
                commit(bit, r)
            })
            .collect();
        self.bit_commitments == expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_range() {
        let proof = RangeProof::prove(18, 0, 120).unwrap();
        assert!(proof.verify(0, 120));
    }

    #[test]
    fn boundary_values() {
        for &v in &[0u64, 50, 100] {
            let proof = RangeProof::prove(v, 0, 100).unwrap();
            assert!(proof.verify(0, 100), "boundary {v}");
        }
    }

    #[test]
    fn out_of_range_errors() {
        assert!(RangeProof::prove(200, 0, 100).is_err());
        assert!(RangeProof::prove(0, 5, 100).is_err());
    }

    #[test]
    fn wrong_range_fails_verify() {
        let proof = RangeProof::prove(25, 18, 120).unwrap();
        assert!(!proof.verify(0, 20));
    }
}
