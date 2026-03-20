//! Sigma protocol: prove knowledge of a discrete-log witness.
//!
//! Proves knowledge of `w` such that `statement = w * G` (in the simulated
//! 64-bit scalar group) via the standard 3-move protocol:
//!
//! 1. **Commit**: prover sends `A = r * G`.
//! 2. **Challenge**: verifier sends `e = H(statement, A)`.
//! 3. **Respond**: prover sends `z = r + e * w`.
//! 4. **Verify**: `z * G == A + e * statement`.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::sigma::{derive_statement, SigmaProof};
//!
//! let witness = 42u64;
//! let statement = derive_statement(witness);
//! let proof = SigmaProof::prove(witness, statement, 99);
//! assert!(proof.verify(statement));
//! ```

/// Generator constant.
const G: u64 = 0x9e37_79b9_7f4a_7c15;

/// Compute `statement = witness * G`.
///
/// # Examples
///
/// ```rust
/// use miden_zk_primitives::sigma::derive_statement;
/// let s = derive_statement(5);
/// assert_ne!(s, 0);
/// ```
#[must_use]
pub fn derive_statement(witness: u64) -> u64 {
    witness.wrapping_mul(G)
}

/// Challenge hash.
#[inline]
fn challenge(statement: u64, a: u64) -> u64 {
    let x = statement
        .wrapping_mul(0x6c62_272e_07bb_0142)
        .wrapping_add(a);
    x ^ (x >> 19) ^ (x << 11)
}

/// A non-interactive Sigma proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigmaProof {
    /// Commitment `A = r * G`.
    pub a: u64,
    /// Response `z = r + e * witness`.
    pub z: u64,
}

impl SigmaProof {
    /// Prove knowledge of `witness` for `statement = witness * G`.
    ///
    /// `r` is the prover's nonce.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::sigma::{derive_statement, SigmaProof};
    /// let w = 7u64;
    /// let stmt = derive_statement(w);
    /// let proof = SigmaProof::prove(w, stmt, 3);
    /// assert!(proof.verify(stmt));
    /// ```
    #[must_use]
    pub fn prove(witness: u64, statement: u64, r: u64) -> Self {
        let a = r.wrapping_mul(G);
        let e = challenge(statement, a);
        let z = r.wrapping_add(e.wrapping_mul(witness));
        Self { a, z }
    }

    /// Verify: `z * G == a + e * statement`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::sigma::{derive_statement, SigmaProof};
    /// let w = 99u64;
    /// let stmt = derive_statement(w);
    /// let proof = SigmaProof::prove(w, stmt, 1234);
    /// assert!(proof.verify(stmt));
    /// ```
    #[must_use]
    pub fn verify(&self, statement: u64) -> bool {
        let e = challenge(statement, self.a);
        let lhs = self.z.wrapping_mul(G);
        let rhs = self.a.wrapping_add(e.wrapping_mul(statement));
        lhs == rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigma_prove_and_verify_ok() {
        let witness = 0xc0ffee_u64;
        let statement = derive_statement(witness);
        let proof = SigmaProof::prove(witness, statement, 0x1234);
        assert!(proof.verify(statement));
    }

    #[test]
    fn prove_and_verify_valid_witness() {
        for w in [1u64, 2, 100, u64::MAX >> 2] {
            let stmt = derive_statement(w);
            let proof = SigmaProof::prove(w, stmt, w.wrapping_add(1));
            assert!(proof.verify(stmt), "failed for w={w}");
        }
    }

    #[test]
    fn tampered_proof_fails() {
        let w = 55u64;
        let stmt = derive_statement(w);
        let mut proof = SigmaProof::prove(w, stmt, 7);
        proof.z ^= 1;
        assert!(!proof.verify(stmt));
    }

    #[test]
    fn wrong_statement_fails() {
        let w = 13u64;
        let stmt = derive_statement(w);
        let proof = SigmaProof::prove(w, stmt, 9);
        let wrong_stmt = derive_statement(w.wrapping_add(1));
        assert!(!proof.verify(wrong_stmt));
    }
}
