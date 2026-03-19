//! Simple Merkle-tree implementation for use in ZK proofs.
//!
//! Leaves are `u64` values hashed with a multiply-and-add scheme.
//! In production, replace the hash function with RPO (Rescue Prime
//! Optimised) as used by Miden.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A binary Merkle tree stored as a flat vector of levels (leaves to root).
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// `levels[0]` = leaves, `levels[last]` = `[root]`.
    levels: Vec<Vec<u64>>,
}

impl MerkleTree {
    /// Build a Merkle tree from `leaves`.
    ///
    /// The number of leaves is padded to the next power of two.
    ///
    /// # Panics
    ///
    /// Panics if `leaves` is empty.
    ///
    /// # Example
    ///
    /// ```
    /// use miden_zk_primitives::merkle::MerkleTree;
    /// let tree = MerkleTree::build(&[1, 2, 3, 4]);
    /// assert_eq!(tree.depth(), 2);
    /// ```
    #[must_use]
    pub fn build(leaves: &[u64]) -> Self {
        assert!(!leaves.is_empty(), "leaves must not be empty");
        let n = leaves.len().next_power_of_two();
        let mut level: Vec<u64> = leaves.to_vec();
        level.resize(n, 0);

        let mut levels = vec![level];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let next: Vec<u64> = prev
                .chunks(2)
                .map(|pair| Self::hash_pair(pair[0], pair[1]))
                .collect();
            levels.push(next);
        }
        Self { levels }
    }

    /// Return the Merkle root.
    #[must_use]
    pub fn root(&self) -> u64 {
        *self.levels.last().unwrap().first().unwrap()
    }

    /// Return the tree depth (number of levels minus one).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.levels.len() - 1
    }

    /// Generate a Merkle proof (sibling hashes) for the leaf at `index`.
    #[must_use]
    pub fn proof(&self, index: usize) -> Vec<u64> {
        let mut siblings = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = if idx.is_multiple_of(2) { idx + 1 } else { idx - 1 };
            siblings.push(level[sibling.min(level.len() - 1)]);
            idx /= 2;
        }
        siblings
    }

    /// Verify a Merkle proof for `leaf` at `index` against the given `root`.
    #[must_use]
    pub fn verify(leaf: u64, index: usize, proof: &[u64], root: u64) -> bool {
        let mut current = leaf;
        let mut idx = index;
        for &sibling in proof {
            current = if idx.is_multiple_of(2) {
                Self::hash_pair(current, sibling)
            } else {
                Self::hash_pair(sibling, current)
            };
            idx /= 2;
        }
        current == root
    }

    fn hash_pair(left: u64, right: u64) -> u64 {
        left.wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(right.wrapping_mul(0x6c62_272e_07bb_0142))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_root() {
        let tree = MerkleTree::build(&[1, 2, 3, 4]);
        let root = tree.root();
        // Root must be deterministic.
        assert_eq!(root, MerkleTree::build(&[1, 2, 3, 4]).root());
    }

    #[test]
    fn proof_verifies() {
        let leaves = vec![10u64, 20, 30, 40];
        let tree = MerkleTree::build(&leaves);
        let root = tree.root();
        for (i, &leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i);
            assert!(
                MerkleTree::verify(leaf, i, &proof, root),
                "proof failed for index {i}"
            );
        }
    }

    #[test]
    fn wrong_leaf_fails() {
        let leaves = vec![10u64, 20, 30, 40];
        let tree = MerkleTree::build(&leaves);
        let proof = tree.proof(0);
        assert!(!MerkleTree::verify(99, 0, &proof, tree.root()));
    }
}
