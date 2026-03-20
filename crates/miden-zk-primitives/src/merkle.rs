//! Sparse Merkle tree with SHA-3-style hash compression.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::merkle::MerkleTree;
//!
//! let tree = MerkleTree::new(vec![10, 20, 30, 40]);
//! let proof = tree.prove(2).unwrap();
//! assert!(tree.verify(2, 30, &proof));
//! ```

use alloc::vec::Vec;

/// A binary Merkle tree over `u64` leaves.
///
/// The tree is always padded to the next power of two with zero-valued leaves.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    nodes: Vec<u64>,
    leaf_count: usize,
}

/// Compress two child hashes into a parent hash.
#[inline]
fn hash_pair(left: u64, right: u64) -> u64 {
    let a = left.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let b = right.wrapping_mul(0x6c62_272e_07bb_0142);
    a.wrapping_add(b) ^ (a >> 17) ^ (b << 13)
}

impl MerkleTree {
    /// Build a new Merkle tree from the given leaves.
    ///
    /// The leaf list is padded with zeros to the next power of two.
    #[must_use]
    pub fn new(leaves: Vec<u64>) -> Self {
        let n = leaves.len().next_power_of_two();
        let mut nodes = vec![0u64; 2 * n];
        // Fill leaf layer
        for (i, &v) in leaves.iter().enumerate() {
            nodes[n + i] = v;
        }
        // Build internal nodes bottom-up
        for i in (1..n).rev() {
            nodes[i] = hash_pair(nodes[2 * i], nodes[2 * i + 1]);
        }
        Self {
            nodes,
            leaf_count: n,
        }
    }

    /// Return the Merkle root.
    #[must_use]
    pub fn root(&self) -> u64 {
        self.nodes[1]
    }

    /// Generate a membership proof (sibling hashes) for leaf at `index`.
    ///
    /// Returns `None` if `index` is out of bounds.
    #[must_use]
    pub fn prove(&self, index: usize) -> Option<Vec<u64>> {
        if index >= self.leaf_count {
            return None;
        }
        let mut proof = Vec::new();
        let mut idx = self.leaf_count + index;
        while idx > 1 {
            let sibling = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            proof.push(self.nodes[sibling]);
            idx /= 2;
        }
        Some(proof)
    }

    /// Verify a membership proof for `leaf` at `index` against the stored root.
    #[must_use]
    pub fn verify(&self, index: usize, leaf: u64, proof: &[u64]) -> bool {
        let mut current = leaf;
        let mut idx = self.leaf_count + index;
        for &sibling in proof {
            current = if idx.is_multiple_of(2) {
                hash_pair(current, sibling)
            } else {
                hash_pair(sibling, current)
            };
            idx /= 2;
        }
        current == self.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_prove_verify() {
        let leaves = vec![1u64, 2, 3, 4];
        let tree = MerkleTree::new(leaves);
        for i in 0..4usize {
            let proof = tree.prove(i).unwrap();
            assert!(tree.verify(i, (i as u64) + 1, &proof), "index {i}");
        }
    }

    #[test]
    fn wrong_leaf_fails() {
        let tree = MerkleTree::new(vec![10, 20, 30, 40]);
        let proof = tree.prove(0).unwrap();
        assert!(!tree.verify(0, 99, &proof));
    }

    #[test]
    fn single_leaf() {
        let tree = MerkleTree::new(vec![42]);
        let proof = tree.prove(0).unwrap();
        assert!(tree.verify(0, 42, &proof));
    }
}
