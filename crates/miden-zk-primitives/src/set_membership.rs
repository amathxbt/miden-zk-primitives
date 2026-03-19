//! # Set Membership Proof
//!
//! Proves that a secret value belongs to a *committed set* without revealing
//! which element it is.
//!
//! ## Construction
//!
//! 1. The set is represented as the leaves of a Merkle tree.
//! 2. The prover holds a secret element `e` and knows the Merkle authentication
//!    path from `e` to the root.
//! 3. The proof is a Merkle membership proof with `e` as the secret input.
//! 4. The verifier only sees the Merkle root (the *set commitment*) and confirms
//!    the path is valid — without learning `e`.

use crate::merkle::{MembershipProof, MerkleTree};

/// A committed set — a Merkle tree over the set elements.
pub struct CommittedSet {
    tree: MerkleTree,
    elements: Vec<u64>,
}

impl CommittedSet {
    /// Build a committed set from a list of elements.
    ///
    /// Elements are padded to the next power of two with `0`.
    pub fn from_elements(elements: &[u64]) -> Self {
        assert!(!elements.is_empty(), "set must not be empty");

        // Pad to next power of two
        let len = elements.len().next_power_of_two();
        let mut padded = elements.to_vec();
        padded.resize(len, 0);

        let tree = MerkleTree::build(&padded);
        CommittedSet { tree, elements: padded }
    }

    /// Return the public commitment (Merkle root) for this set.
    pub fn commitment(&self) -> [miden_core::Felt; 4] {
        self.tree.root()
    }

    /// Generate a membership proof for `element`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidMerklePath`] if the element is not in the set.
    pub fn membership_proof(&self, element: u64) -> crate::Result<MembershipProof> {
        let index = self.elements
            .iter()
            .position(|&e| e == element)
            .ok_or_else(|| {
                crate::Error::InvalidMerklePath(format!(
                    "element {element} not found in the committed set"
                ))
            })?;

        self.tree.membership_proof(index as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_proves_membership() {
        let set = CommittedSet::from_elements(&[10, 20, 30, 40]);
        let root = set.commitment();
        let proof = set.membership_proof(30).expect("30 is in the set");
        proof.verify(root).expect("membership proof should verify");
    }

    #[test]
    fn non_member_returns_error() {
        let set = CommittedSet::from_elements(&[10, 20, 30, 40]);
        assert!(set.membership_proof(99).is_err(), "99 is not in the set");
    }

    #[test]
    fn different_sets_different_commitments() {
        let s1 = CommittedSet::from_elements(&[1, 2, 3, 4]);
        let s2 = CommittedSet::from_elements(&[1, 2, 3, 5]);
        assert_ne!(s1.commitment(), s2.commitment());
    }
}
