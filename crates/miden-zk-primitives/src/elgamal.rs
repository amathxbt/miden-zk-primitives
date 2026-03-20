//! ElGamal public-key encryption in a 64-bit scalar group.
//!
//! Uses a fixed generator `G` and wrapping multiplication as the group law.
//! The encryption is IND-CPA in this simulated group.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::elgamal::{ElGamalKeypair, ElGamalCiphertext};
//!
//! let (pk, sk) = ElGamalKeypair::generate(12345);
//! let ct = ElGamalCiphertext::encrypt(pk, 999, 7777);
//! let pt = ct.decrypt(sk);
//! assert_eq!(pt, 999);
//! ```

use alloc::vec::Vec;

/// Generator constant for the simulated group.
const G: u64 = 0x9e37_79b9_7f4a_7c15;

/// Domain-separated hash used only for masking (not for group ops).
#[inline]
fn hash(a: u64, b: u64) -> u64 {
    let x = a.wrapping_mul(0x6c62_272e_07bb_0142).wrapping_add(b);
    x ^ (x >> 27) ^ (x << 11)
}

/// An ElGamal key pair.
#[derive(Debug, Clone, Copy)]
pub struct ElGamalKeypair {
    /// Public key: `sk * G`.
    pub pk: u64,
    /// Secret key.
    pub sk: u64,
}

impl ElGamalKeypair {
    /// Generate a key pair from a secret scalar `sk`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::elgamal::ElGamalKeypair;
    /// let (pk, sk) = ElGamalKeypair::generate(42);
    /// assert_ne!(pk, 0);
    /// ```
    #[must_use]
    pub fn generate(sk: u64) -> (u64, u64) {
        let pk = sk.wrapping_mul(G);
        (pk, sk)
    }
}

/// An ElGamal ciphertext `(C1, C2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    /// First component: `r * G`.
    pub c1: u64,
    /// Second component: `plaintext XOR hash(r * pk)`.
    pub c2: u64,
}

impl ElGamalCiphertext {
    /// Encrypt `plaintext` under public key `pk` with ephemeral scalar `r`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::elgamal::ElGamalCiphertext;
    /// let (pk, sk) = miden_zk_primitives::elgamal::ElGamalKeypair::generate(7);
    /// let ct = ElGamalCiphertext::encrypt(pk, 42, 99);
    /// assert_eq!(ct.decrypt(sk), 42);
    /// ```
    #[must_use]
    pub fn encrypt(pk: u64, plaintext: u64, r: u64) -> Self {
        let c1 = r.wrapping_mul(G);
        let shared = r.wrapping_mul(pk);
        let mask = hash(shared, 0xcafe_babe);
        let c2 = plaintext ^ mask;
        Self { c1, c2 }
    }

    /// Decrypt using secret key `sk`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::elgamal::{ElGamalKeypair, ElGamalCiphertext};
    /// let (pk, sk) = ElGamalKeypair::generate(123);
    /// let ct = ElGamalCiphertext::encrypt(pk, 0xABCD, 456);
    /// assert_eq!(ct.decrypt(sk), 0xABCD);
    /// ```
    #[must_use]
    pub fn decrypt(self, sk: u64) -> u64 {
        let shared = sk.wrapping_mul(self.c1);
        let mask = hash(shared, 0xcafe_babe);
        self.c2 ^ mask
    }
}

/// Batch-encrypt a slice of plaintexts under `pk`.
///
/// Each message uses its index as the ephemeral scalar (for determinism).
///
/// # Examples
///
/// ```rust
/// use miden_zk_primitives::elgamal::{ElGamalKeypair, batch_encrypt};
/// let (pk, sk) = ElGamalKeypair::generate(7);
/// let cts = batch_encrypt(pk, &[1, 2, 3]);
/// assert_eq!(cts[0].decrypt(sk), 1);
/// assert_eq!(cts[2].decrypt(sk), 3);
/// ```
#[must_use]
pub fn batch_encrypt(pk: u64, plaintexts: &[u64]) -> Vec<ElGamalCiphertext> {
    plaintexts
        .iter()
        .enumerate()
        .map(|(i, &p)| ElGamalCiphertext::encrypt(pk, p, (i as u64) + 1))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (pk, sk) = ElGamalKeypair::generate(0xdead_beef);
        for &msg in &[0u64, 1, 42, u64::MAX, 0x1234_5678] {
            let ct = ElGamalCiphertext::encrypt(pk, msg, 0xface);
            assert_eq!(ct.decrypt(sk), msg, "failed for msg={msg}");
        }
    }

    #[test]
    fn different_r_different_ciphertext() {
        let (pk, _sk) = ElGamalKeypair::generate(99);
        let ct1 = ElGamalCiphertext::encrypt(pk, 42, 1);
        let ct2 = ElGamalCiphertext::encrypt(pk, 42, 2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn batch_roundtrip() {
        let (pk, sk) = ElGamalKeypair::generate(7);
        let msgs = [10u64, 20, 30, 40];
        let cts = batch_encrypt(pk, &msgs);
        for (ct, &expected) in cts.iter().zip(msgs.iter()) {
            assert_eq!(ct.decrypt(sk), expected);
        }
    }
}
