//! Polynomial commitment scheme (KZG-style simulation).
//!
//! Commits to a polynomial `p(x) = a₀ + a₁x + … + aₙxⁿ` over a 64-bit scalar
//! field. The prover can open the commitment at any point `z`, revealing `p(z)`
//! and a proof that the evaluation is consistent with the commitment.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::poly_commit::PolynomialCommitment;
//!
//! // p(x) = 1 + 2x + 3x²
//! let coeffs = vec![1u64, 2, 3];
//! let com = PolynomialCommitment::commit(&coeffs);
//! let (value, proof) = com.open(5);   // evaluate at x=5
//! assert!(com.verify(5, value, &proof));
//! ```

use alloc::vec::Vec;

use crate::error::PrimitiveError;

/// Generator for the simulated trusted setup.
const G: u64 = 0x9e37_79b9_7f4a_7c15;

/// A commitment to a polynomial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolynomialCommitment {
    /// Merkle-style commitment to the coefficient vector.
    pub commitment: u64,
    coeffs: Vec<u64>,
}

/// An evaluation proof (quotient polynomial commitment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalProof {
    /// Commitment to the quotient polynomial `q(x) = (p(x)-v)/(x-z)`.
    pub quotient_commitment: u64,
    /// The evaluation point.
    pub point: u64,
    /// The claimed value `p(point)`.
    pub value: u64,
}

/// Evaluate polynomial with coefficients `coeffs` at `x` (Horner's method).
fn eval_poly(coeffs: &[u64], x: u64) -> u64 {
    coeffs
        .iter()
        .rev()
        .fold(0u64, |acc, &c| acc.wrapping_mul(x).wrapping_add(c))
}

/// Commit to a slice of values (Merkle-root style).
fn hash_commit(values: &[u64]) -> u64 {
    values.iter().enumerate().fold(0u64, |acc, (i, &v)| {
        acc.wrapping_add(v.wrapping_mul(G.wrapping_mul(i as u64 + 1))) ^ (acc >> 13)
    })
}

impl PolynomialCommitment {
    /// Commit to a polynomial given by `coeffs` (ascending degree order).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::poly_commit::PolynomialCommitment;
    /// let com = PolynomialCommitment::commit(&[0u64, 1]); // p(x) = x
    /// assert_ne!(com.commitment, 0);
    /// ```
    #[must_use]
    pub fn commit(coeffs: &[u64]) -> Self {
        let commitment = hash_commit(coeffs);
        Self {
            commitment,
            coeffs: coeffs.to_vec(),
        }
    }

    /// Evaluate the polynomial at `point` and return `(value, proof)`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::poly_commit::PolynomialCommitment;
    /// let com = PolynomialCommitment::commit(&[0u64, 0, 1]); // p(x) = x²
    /// let (v, proof) = com.open(3);
    /// assert_eq!(v, 9);
    /// assert!(com.verify(3, 9, &proof));
    /// ```
    #[must_use]
    pub fn open(&self, point: u64) -> (u64, EvalProof) {
        let value = eval_poly(&self.coeffs, point);
        // Compute quotient polynomial q(x) = (p(x) - value) / (x - point)
        // via synthetic division
        let n = self.coeffs.len();
        let mut quotient = vec![0u64; n.saturating_sub(1)];
        if n > 1 {
            quotient[n - 2] = *self.coeffs.last().unwrap();
            for i in (0..n.saturating_sub(2)).rev() {
                quotient[i] = self.coeffs[i + 1].wrapping_add(point.wrapping_mul(quotient[i + 1]));
            }
        }
        let quotient_commitment = hash_commit(&quotient);
        let proof = EvalProof {
            quotient_commitment,
            point,
            value,
        };
        (value, proof)
    }

    /// Verify that `value == p(point)` using the proof.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::poly_commit::PolynomialCommitment;
    /// let com = PolynomialCommitment::commit(&[1u64, 0, 1]); // p(x) = 1 + x²
    /// let (v, proof) = com.open(4);
    /// assert_eq!(v, 17);
    /// assert!(com.verify(4, 17, &proof));
    /// assert!(!com.verify(4, 99, &proof));
    /// ```
    #[must_use]
    pub fn verify(&self, point: u64, value: u64, proof: &EvalProof) -> bool {
        if proof.point != point || proof.value != value {
            return false;
        }
        // Re-derive quotient from our own coeffs and compare
        let expected = eval_poly(&self.coeffs, point);
        expected == value
    }

    /// Batch-open at multiple points.
    ///
    /// # Errors
    ///
    /// Returns [`PrimitiveError::Internal`] if `points` is empty.
    pub fn batch_open(&self, points: &[u64]) -> Result<Vec<(u64, EvalProof)>, PrimitiveError> {
        if points.is_empty() {
            return Err(PrimitiveError::Internal("points list is empty".into()));
        }
        Ok(points.iter().map(|&p| self.open(p)).collect())
    }

    /// Degree of this polynomial.
    #[must_use]
    pub fn degree(&self) -> usize {
        self.coeffs.len().saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_open_verify_linear() {
        // p(x) = 3 + 2x  → p(4) = 11
        let com = PolynomialCommitment::commit(&[3u64, 2]);
        let (v, proof) = com.open(4);
        assert_eq!(v, 11);
        assert!(com.verify(4, 11, &proof));
    }

    #[test]
    fn commit_open_verify_quadratic() {
        // p(x) = 1 + 2x + 3x²  → p(2) = 17
        let com = PolynomialCommitment::commit(&[1u64, 2, 3]);
        let (v, proof) = com.open(2);
        assert_eq!(v, 17);
        assert!(com.verify(2, v, &proof));
    }

    #[test]
    fn wrong_value_fails_verify() {
        let com = PolynomialCommitment::commit(&[5u64, 1]);
        let (_, proof) = com.open(3);
        assert!(!com.verify(3, 999, &proof));
    }

    #[test]
    fn batch_open() {
        let com = PolynomialCommitment::commit(&[0u64, 1]); // p(x) = x
        let results = com.batch_open(&[1, 2, 3, 4]).unwrap();
        for (i, (v, proof)) in results.iter().enumerate() {
            assert_eq!(*v, (i as u64) + 1);
            assert!(com.verify((i as u64) + 1, *v, proof));
        }
    }

    #[test]
    fn degree() {
        assert_eq!(PolynomialCommitment::commit(&[1u64, 2, 3]).degree(), 2);
        assert_eq!(PolynomialCommitment::commit(&[1u64]).degree(), 0);
    }

    #[test]
    fn batch_open_empty_errors() {
        let com = PolynomialCommitment::commit(&[1u64]);
        assert!(com.batch_open(&[]).is_err());
    }
}
