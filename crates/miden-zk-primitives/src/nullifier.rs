//! # Nullifier
//!
//! A *nullifier* is a publicly-computable, collision-resistant tag derived from a
//! secret. It enables *single-use* semantics in private protocols:
//!
//! - The prover publishes `nullifier = RPO([secret, context, 0, 0])`.
//! - Anyone can store seen nullifiers in a set.
//! - If the same secret is reused, the same nullifier reappears → *double-spend detected*.
//! - The nullifier reveals nothing about the secret (pre-image resistance of RPO).
//!
//! ## Example: private voting
//!
//! Each voter has a secret key `k`. Their nullifier for election `e` is:
//!
//! ```text
//! nullifier = RPO([k, election_id, 0, 0])
//! ```
//!
//! The chain records the nullifier. Submitting a second vote with the same `k`
//! would produce the same nullifier, which is already in the set → rejected.

use miden_core::{crypto::hash::{Rpo256, RpoDigest}, Felt, Word, ZERO};

/// A nullifier: a single-use tag derived from a secret key and a context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Nullifier(Word);

impl Nullifier {
    /// Derive a nullifier from a `secret_key` and a `context_tag`.
    ///
    /// The derivation is `RPO([secret_key, context_tag, 0, 0])`.
    ///
    /// `context_tag` should uniquely identify the protocol context (e.g., an
    /// election ID) so that the same secret key in different contexts produces
    /// different nullifiers.
    pub fn derive(secret_key: u64, context_tag: u64) -> Self {
        let elements = [
            Felt::new(secret_key),
            Felt::new(context_tag),
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
        ];
        let digest: Word = Rpo256::hash_elements(&elements).into();
        Nullifier(digest)
    }

    /// Return the raw `Word` value.
    pub fn as_word(&self) -> &Word {
        &self.0
    }

    /// Return the nullifier as a hex string (for display / storage).
    pub fn to_hex(&self) -> String {
        self.0
            .iter()
            .map(|f| format!("{:016x}", f.as_int()))
            .collect::<Vec<_>>()
            .join("")
    }
}

impl std::fmt::Display for Nullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", &self.to_hex()[..16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_inputs_same_nullifier() {
        let n1 = Nullifier::derive(42, 1000);
        let n2 = Nullifier::derive(42, 1000);
        assert_eq!(n1, n2);
    }

    #[test]
    fn different_keys_different_nullifiers() {
        let n1 = Nullifier::derive(1, 1000);
        let n2 = Nullifier::derive(2, 1000);
        assert_ne!(n1, n2);
    }

    #[test]
    fn different_contexts_different_nullifiers() {
        let n1 = Nullifier::derive(42, 1000);
        let n2 = Nullifier::derive(42, 2000);
        assert_ne!(n1, n2, "same key in different contexts should produce different nullifiers");
    }

    #[test]
    fn display_format() {
        let n = Nullifier::derive(0, 0);
        let s = n.to_string();
        assert!(s.starts_with("0x"), "display should be hex");
    }
}
