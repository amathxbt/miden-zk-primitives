//! Sparse Merkle Tree (SMT) with default-value leaves.
//!
//! A full binary tree of depth `D` over a 64-bit key space. Unset leaves
//! default to `0`. Supports membership **and** non-membership proofs.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::sparse_merkle::SparseMerkleTree;
//!
//! let mut smt = SparseMerkleTree::new(4); // depth 4, 16 leaves
//! smt.insert(2, 42);
//! smt.insert(7, 99);
//!
//! let (value, proof) = smt.get_with_proof(2);
//! assert_eq!(value, 42);
//! assert!(smt.verify_proof(2, 42, &proof));
//!
//! // Non-membership proof for key 5 (never inserted)
//! let (v2, proof2) = smt.get_with_proof(5);
//! assert_eq!(v2, 0); // default
//! assert!(smt.verify_proof(5, 0, &proof2));
//! ```

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// A sparse Merkle tree of a fixed depth.
#[derive(Debug, Clone)]
pub struct SparseMerkleTree {
    depth: usize,
    leaves: BTreeMap<u64, u64>,
}

/// A Merkle proof (sibling hashes from leaf to root).
#[derive(Debug, Clone)]
pub struct SparseMerkleProof {
    /// Sibling hashes from leaf level up to (but not including) root.
    pub siblings: Vec<u64>,
}

/// Hash two child nodes into a parent.
#[inline]
fn hash_node(left: u64, right: u64) -> u64 {
    let a = left.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let b = right.wrapping_mul(0x6c62_272e_07bb_0142);
    a.wrapping_add(b) ^ (a >> 17) ^ (b << 13)
}

impl SparseMerkleTree {
    /// Create a new sparse Merkle tree with `depth` levels.
    ///
    /// The tree has `2^depth` leaf slots, all initialised to `0`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::sparse_merkle::SparseMerkleTree;
    /// let smt = SparseMerkleTree::new(8);
    /// assert_eq!(smt.root(), smt.root()); // deterministic empty root
    /// ```
    #[must_use]
    pub fn new(depth: usize) -> Self {
        Self {
            depth,
            leaves: BTreeMap::new(),
        }
    }

    /// Insert or update `key → value`.
    pub fn insert(&mut self, key: u64, value: u64) {
        if value == 0 {
            self.leaves.remove(&key);
        } else {
            self.leaves.insert(key, value);
        }
    }

    /// Get the value stored at `key` (returns `0` if not set).
    #[must_use]
    pub fn get(&self, key: u64) -> u64 {
        *self.leaves.get(&key).unwrap_or(&0)
    }

    /// Number of leaf slots (`2^depth`).
    #[must_use]
    pub fn capacity(&self) -> u64 {
        1u64 << self.depth
    }

    /// Compute the Merkle root.
    #[must_use]
    pub fn root(&self) -> u64 {
        self.compute_node(0, self.depth)
    }

    /// Recursively compute the hash of a subtree.
    fn compute_node(&self, index: u64, level: usize) -> u64 {
        if level == 0 {
            return self.get(index);
        }
        let left = self.compute_node(index * 2, level - 1);
        let right = self.compute_node(index * 2 + 1, level - 1);
        hash_node(left, right)
    }

    /// Get value at `key` together with a Merkle proof.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::sparse_merkle::SparseMerkleTree;
    /// let mut smt = SparseMerkleTree::new(4);
    /// smt.insert(3, 77);
    /// let (v, proof) = smt.get_with_proof(3);
    /// assert_eq!(v, 77);
    /// assert!(smt.verify_proof(3, 77, &proof));
    /// ```
    #[must_use]
    pub fn get_with_proof(&self, key: u64) -> (u64, SparseMerkleProof) {
        let value = self.get(key);
        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = key;
        for level in 0..self.depth {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            siblings.push(self.compute_node(sibling_idx, level));
            idx /= 2;
        }
        (value, SparseMerkleProof { siblings })
    }

    /// Verify a proof for `(key, value)` against the stored root.
    ///
    /// Works for both membership proofs (value != 0) and
    /// non-membership proofs (value == 0).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::sparse_merkle::SparseMerkleTree;
    /// let mut smt = SparseMerkleTree::new(4);
    /// smt.insert(0, 100);
    /// let (v, proof) = smt.get_with_proof(0);
    /// assert!(smt.verify_proof(0, 100, &proof));
    /// assert!(!smt.verify_proof(0, 101, &proof));
    /// ```
    #[must_use]
    pub fn verify_proof(&self, key: u64, value: u64, proof: &SparseMerkleProof) -> bool {
        let mut current = value;
        let mut idx = key;
        for &sibling in &proof.siblings {
            current = if idx.is_multiple_of(2) {
                hash_node(current, sibling)
            } else {
                hash_node(sibling, current)
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
    fn insert_and_prove_membership() {
        let mut smt = SparseMerkleTree::new(4);
        smt.insert(3, 42);
        smt.insert(10, 99);
        for &(k, v) in &[(3u64, 42u64), (10, 99)] {
            let (val, proof) = smt.get_with_proof(k);
            assert_eq!(val, v);
            assert!(smt.verify_proof(k, v, &proof), "key={k}");
        }
    }

    #[test]
    fn non_membership_proof() {
        let mut smt = SparseMerkleTree::new(4);
        smt.insert(1, 111);
        let (v, proof) = smt.get_with_proof(5); // never inserted
        assert_eq!(v, 0);
        assert!(smt.verify_proof(5, 0, &proof));
    }

    #[test]
    fn wrong_value_fails() {
        let mut smt = SparseMerkleTree::new(4);
        smt.insert(2, 55);
        let (_, proof) = smt.get_with_proof(2);
        assert!(!smt.verify_proof(2, 56, &proof));
    }

    #[test]
    fn update_changes_root() {
        let mut smt = SparseMerkleTree::new(4);
        smt.insert(0, 1);
        let r1 = smt.root();
        smt.insert(0, 2);
        let r2 = smt.root();
        assert_ne!(r1, r2);
    }

    #[test]
    fn empty_tree_consistent() {
        let smt = SparseMerkleTree::new(4);
        let (v, proof) = smt.get_with_proof(7);
        assert_eq!(v, 0);
        assert!(smt.verify_proof(7, 0, &proof));
    }
}
