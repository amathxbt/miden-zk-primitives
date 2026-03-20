//! Set-membership proof: prove that a secret element belongs to a public set.
//!
//! Uses a Merkle tree over the set elements.  The prover commits to the
//! element position and supplies the Merkle path.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::set_membership::SetMembershipProof;
//!
//! let set = vec![10u64, 20, 30, 40];
//! let proof = SetMembershipProof::prove(&set, 1).unwrap();
//! assert!(proof.verify(&set));
//! ```

use alloc::vec::Vec;

use crate::{error::PrimitiveError, merkle::MerkleTree};

/// A Merkle-path membership proof.
#[derive(Debug, Clone)]
pub struct SetMembershipProof {
    /// The element being proved.
    pub element: u64,
    /// Index of the element in the set.
    pub index: usize,
    /// Sibling hashes along the Merkle path.
    pub path: Vec<u64>,
    /// Merkle root of the full set.
    pub root: u64,
}

impl SetMembershipProof {
    /// Prove that `set[index]` is a member of `set`.
    ///
    /// # Errors
    ///
    /// Returns [`PrimitiveError::NotAMember`] when `index >= set.len()`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::set_membership::SetMembershipProof;
    /// let set = vec![1u64, 2, 3, 4];
    /// let proof = SetMembershipProof::prove(&set, 2).unwrap();
    /// assert!(proof.verify(&set));
    /// ```
    pub fn prove(set: &[u64], index: usize) -> Result<Self, PrimitiveError> {
        if index >= set.len() {
            return Err(PrimitiveError::NotAMember);
        }
        let tree = MerkleTree::new(set.to_vec());
        let path = tree.prove(index).ok_or(PrimitiveError::NotAMember)?;
        Ok(Self {
            element: set[index],
            index,
            path,
            root: tree.root(),
        })
    }

    /// Verify this proof against `set`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::set_membership::SetMembershipProof;
    /// let set = vec![100u64, 200, 300];
    /// let proof = SetMembershipProof::prove(&set, 0).unwrap();
    /// assert!(proof.verify(&set));
    /// ```
    #[must_use]
    pub fn verify(&self, set: &[u64]) -> bool {
        let tree = MerkleTree::new(set.to_vec());
        tree.root() == self.root && tree.verify(self.index, self.element, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify() {
        let set = vec![10u64, 20, 30, 40];
        for idx in 0..set.len() {
            let proof = SetMembershipProof::prove(&set, idx).unwrap();
            assert!(proof.verify(&set), "index {idx}");
        }
    }

    #[test]
    fn wrong_element_fails() {
        let set = vec![10u64, 20, 30, 40];
        let mut proof = SetMembershipProof::prove(&set, 0).unwrap();
        proof.element = 99;
        assert!(!proof.verify(&set));
    }

    #[test]
    fn out_of_bounds_errors() {
        let set = vec![1u64, 2, 3];
        assert!(SetMembershipProof::prove(&set, 5).is_err());
    }
}
