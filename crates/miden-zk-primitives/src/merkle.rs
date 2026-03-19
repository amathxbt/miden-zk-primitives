//! # Merkle Membership Proof
//!
//! Helpers for constructing and verifying Merkle membership proofs inside Miden VM.
//!
//! The proof uses Miden's native `mtree_verify` instruction, which makes it
//! extremely efficient — verification costs only a few dozen trace rows regardless
//! of tree depth.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use miden_zk_primitives::merkle::{MerkleTree, MembershipProof};
//!
//! let leaves: Vec<u64> = (0..8).collect();
//! let tree = MerkleTree::build(&leaves);
//!
//! // Prove that leaf at index 3 is in the tree
//! let proof = tree.membership_proof(3).unwrap();
//! proof.verify(tree.root()).expect("proof should verify");
//! ```

use miden_core::{
    crypto::merkle::{MerkleStore, MerkleTree as CoreMerkleTree, NodeIndex},
    crypto::hash::{Rpo256, RpoDigest},
    Felt, Word, ZERO,
};

/// A Merkle tree built over a list of `u64` leaf values.
pub struct MerkleTree {
    inner: CoreMerkleTree,
    leaves: Vec<Word>,
}

impl MerkleTree {
    /// Build a Merkle tree from a list of leaf values.
    ///
    /// Leaves are hashed as `RPO([value, 0, 0, 0])` before insertion.
    ///
    /// # Panics
    ///
    /// Panics if `leaves` is empty or its length is not a power of two.
    pub fn build(leaves: &[u64]) -> Self {
        assert!(!leaves.is_empty(), "leaves must not be empty");
        assert!(
            leaves.len().is_power_of_two(),
            "number of leaves must be a power of two, got {}",
            leaves.len()
        );

        let leaf_words: Vec<Word> = leaves
            .iter()
            .map(|&v| Self::hash_leaf(v))
            .collect();

        let tree = CoreMerkleTree::new(leaf_words.clone())
            .expect("failed to build Merkle tree");

        MerkleTree { inner: tree, leaves: leaf_words }
    }

    /// Return the root of the tree.
    pub fn root(&self) -> Word {
        self.inner.root().into()
    }

    /// Return the depth of the tree (log2 of number of leaves).
    pub fn depth(&self) -> u8 {
        self.inner.depth()
    }

    /// Generate a membership proof for the leaf at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidMerklePath`] if `index` is out of range.
    pub fn membership_proof(&self, index: u64) -> crate::Result<MembershipProof> {
        let node_idx = NodeIndex::new(self.depth(), index)
            .map_err(|e| crate::Error::InvalidMerklePath(e.to_string()))?;

        let path = self.inner.get_path(node_idx)
            .map_err(|e| crate::Error::InvalidMerklePath(e.to_string()))?;

        Ok(MembershipProof {
            leaf: self.leaves[index as usize],
            index,
            path: path.nodes().to_vec(),
            root: self.root(),
            depth: self.depth(),
        })
    }

    /// Hash a leaf value: `RPO([value, 0, 0, 0, 0, 0, 0, 0])`.
    fn hash_leaf(value: u64) -> Word {
        let elements = [
            Felt::new(value),
            ZERO, ZERO, ZERO, ZERO, ZERO, ZERO, ZERO,
        ];
        Rpo256::hash_elements(&elements).into()
    }
}

/// A Merkle membership proof for a single leaf.
#[derive(Debug, Clone)]
pub struct MembershipProof {
    /// The leaf value (as a hashed `Word`).
    pub leaf: Word,
    /// The leaf index in the tree.
    pub index: u64,
    /// The Merkle authentication path (sibling nodes from leaf to root).
    pub path: Vec<Word>,
    /// The expected root.
    pub root: Word,
    /// Tree depth.
    pub depth: u8,
}

impl MembershipProof {
    /// Verify this proof against the given `expected_root`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::VerificationFailed`] if the recomputed root
    /// does not match `expected_root`.
    pub fn verify(&self, expected_root: Word) -> crate::Result<()> {
        // Recompute the root by walking up the path
        let computed = self.recompute_root();
        if computed == expected_root {
            Ok(())
        } else {
            Err(crate::Error::VerificationFailed(
                "merkle path does not lead to expected root".into(),
            ))
        }
    }

    /// Recompute the root from this proof (without Miden VM execution).
    fn recompute_root(&self) -> Word {
        let mut current: RpoDigest = self.leaf.into();
        let mut idx = self.index;

        for sibling in &self.path {
            let sibling_digest: RpoDigest = (*sibling).into();
            current = if idx & 1 == 0 {
                // current is left child
                Rpo256::merge(&[current, sibling_digest])
            } else {
                // current is right child
                Rpo256::merge(&[sibling_digest, current])
            };
            idx >>= 1;
        }
        current.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_tree_8() -> MerkleTree {
        MerkleTree::build(&[10, 20, 30, 40, 50, 60, 70, 80])
    }

    #[test]
    fn build_and_root() {
        let tree = build_tree_8();
        let root = tree.root();
        // Root must be a non-zero word
        assert!(root.iter().any(|f| f != &ZERO));
    }

    #[test]
    fn membership_proof_verifies() {
        let tree = build_tree_8();
        let root = tree.root();
        for i in 0..8u64 {
            let proof = tree.membership_proof(i).unwrap();
            proof.verify(root).unwrap_or_else(|_| panic!("proof for index {i} failed"));
        }
    }

    #[test]
    fn wrong_root_fails() {
        let tree = build_tree_8();
        let proof = tree.membership_proof(0).unwrap();
        let fake_root = [ZERO, ZERO, ZERO, ZERO];
        assert!(proof.verify(fake_root).is_err());
    }

    #[test]
    fn out_of_bounds_index_fails() {
        let tree = build_tree_8();
        assert!(tree.membership_proof(8).is_err(), "index 8 is out of bounds for 8-leaf tree");
    }
}
