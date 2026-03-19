//! Set-membership proof: prove an element belongs to a committed set
//! without revealing *which* element it is.

use crate::error::PrimitiveError;

/// A (simulated) set-membership proof.
#[derive(Debug, Clone)]
pub struct SetMembershipProof {
    /// Merkle-root commitment of the set.
    root: u64,
    /// Index of the element (kept private in a real ZK proof).
    index: usize,
}

impl SetMembershipProof {
    /// Generate a membership proof for `element` in `set`.
    ///
    /// Returns `Err(PrimitiveError::NotAMember)` if the element is absent.
    ///
    /// # Example
    /// ```
    /// use miden_zk_primitives::set_membership::SetMembershipProof;
    /// let set = vec![10u64, 20, 30];
    /// let proof = SetMembershipProof::prove(20, &set).unwrap();
    /// assert!(proof.verify(&set));
    /// ```
    pub fn prove(element: u64, set: &[u64]) -> Result<Self, PrimitiveError> {
        let index = set
            .iter()
            .position(|&x| x == element)
            .ok_or(PrimitiveError::NotAMember)?;

        let root = Self::merkle_root(set);
        Ok(Self { root, index })
    }

    /// Verify the proof against the same set.
    pub fn verify(&self, set: &[u64]) -> bool {
        Self::merkle_root(set) == self.root && self.index < set.len()
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Compute a simple Merkle-style root over the set elements.
    fn merkle_root(set: &[u64]) -> u64 {
        set.iter().fold(0u64, |acc, &x| {
            acc.wrapping_add(x.wrapping_mul(0x9e37_79b9_7f4a_7c15))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_proof_valid() {
        let set = vec![1u64, 2, 3, 4, 5];
        let proof = SetMembershipProof::prove(3, &set).unwrap();
        assert!(proof.verify(&set));
    }

    #[test]
    fn non_member_rejected() {
        let set = vec![1u64, 2, 3];
        let err = SetMembershipProof::prove(99, &set).unwrap_err();
        assert_eq!(err, PrimitiveError::NotAMember);
    }

    #[test]
    fn tampered_set_invalidates_proof() {
        let set = vec![1u64, 2, 3];
        let proof = SetMembershipProof::prove(2, &set).unwrap();
        let tampered = vec![1u64, 99, 3];
        assert!(!proof.verify(&tampered));
    }
}
