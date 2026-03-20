//! Vector commitment: commit to an ordered vector of values.
//!
//! Supports position-binding opening proofs so a verifier can confirm that
//! a particular value occupies a specific position in the committed vector.
//!
//! Internally this is a Merkle tree whose leaves are the vector elements.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::vector_commitment::VectorCommitment;
//!
//! let vc = VectorCommitment::commit(vec![10u64, 20, 30, 40]);
//! let proof = vc.open(2).unwrap();
//! assert!(vc.verify(2, 30, &proof));
//! assert!(!vc.verify(2, 99, &proof));
//! ```

use alloc::vec::Vec;

use crate::merkle::MerkleTree;

/// A position-binding vector commitment.
#[derive(Debug, Clone)]
pub struct VectorCommitment {
    tree: MerkleTree,
    length: usize,
}

/// An opening proof for a single position.
#[derive(Debug, Clone)]
pub struct OpeningProof {
    /// Merkle sibling path.
    pub path: Vec<u64>,
}

impl VectorCommitment {
    /// Commit to a vector of values.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::vector_commitment::VectorCommitment;
    /// let vc = VectorCommitment::commit(vec![1u64, 2, 3]);
    /// assert_ne!(vc.commitment(), 0);
    /// ```
    #[must_use]
    pub fn commit(values: Vec<u64>) -> Self {
        let length = values.len();
        let tree = MerkleTree::new(values);
        Self { tree, length }
    }

    /// The commitment value (Merkle root).
    #[must_use]
    pub fn commitment(&self) -> u64 {
        self.tree.root()
    }

    /// Open position `index` and return an [`OpeningProof`].
    ///
    /// Returns `None` when `index >= len`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::vector_commitment::VectorCommitment;
    /// let vc = VectorCommitment::commit(vec![5u64, 10, 15]);
    /// assert!(vc.open(1).is_some());
    /// assert!(vc.open(99).is_none());
    /// ```
    #[must_use]
    pub fn open(&self, index: usize) -> Option<OpeningProof> {
        if index >= self.length {
            return None;
        }
        let path = self.tree.prove(index)?;
        Some(OpeningProof { path })
    }

    /// Verify that `value` is at `index` in this commitment.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::vector_commitment::VectorCommitment;
    /// let vc = VectorCommitment::commit(vec![100u64, 200, 300, 400]);
    /// let proof = vc.open(3).unwrap();
    /// assert!(vc.verify(3, 400, &proof));
    /// ```
    #[must_use]
    pub fn verify(&self, index: usize, value: u64, proof: &OpeningProof) -> bool {
        self.tree.verify(index, value, &proof.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_open_verify() {
        let values: Vec<u64> = (1..=8).collect();
        let vc = VectorCommitment::commit(values.clone());
        for (i, &v) in values.iter().enumerate() {
            let proof = vc.open(i).unwrap();
            assert!(vc.verify(i, v, &proof), "index {i}");
        }
    }

    #[test]
    fn wrong_value_fails() {
        let vc = VectorCommitment::commit(vec![10u64, 20, 30]);
        let proof = vc.open(0).unwrap();
        assert!(!vc.verify(0, 99, &proof));
    }

    #[test]
    fn out_of_bounds_returns_none() {
        let vc = VectorCommitment::commit(vec![1u64, 2]);
        assert!(vc.open(5).is_none());
    }

    #[test]
    fn single_element() {
        let vc = VectorCommitment::commit(vec![777u64]);
        let proof = vc.open(0).unwrap();
        assert!(vc.verify(0, 777, &proof));
    }
}
