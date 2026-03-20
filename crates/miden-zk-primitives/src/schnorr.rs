//! Schnorr digital signature scheme in a 64-bit scalar group.
//!
//! Uses wrapping multiplication with generator `G` as the group law.
//! The scheme satisfies the standard Schnorr equation:
//! `s * G == R + e * pk`
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::schnorr::{SchnorrKeypair, sign, verify};
//!
//! let (pk, sk) = SchnorrKeypair::generate(42);
//! let sig = sign(sk, pk, b"hello world", 99);
//! assert!(verify(pk, b"hello world", sig));
//! ```

/// Generator constant.
const G: u64 = 0x9e37_79b9_7f4a_7c15;

/// Hash function for challenge computation.
#[inline]
fn challenge_hash(r: u64, pk: u64, msg_hash: u64) -> u64 {
    let x = r
        .wrapping_mul(0x6c62_272e_07bb_0142)
        .wrapping_add(pk)
        .wrapping_add(msg_hash);
    x ^ (x >> 17) ^ (x << 13)
}

/// Hash a message to a `u64` scalar.
#[inline]
fn hash_message(msg: &[u8]) -> u64 {
    msg.iter().enumerate().fold(0u64, |acc, (i, &b)| {
        acc.wrapping_add(u64::from(b).wrapping_mul((i as u64 + 1).wrapping_mul(G)))
    })
}

/// A Schnorr key pair.
#[derive(Debug, Clone, Copy)]
pub struct SchnorrKeypair {
    /// Public key: `sk * G`.
    pub pk: u64,
    /// Secret key.
    pub sk: u64,
}

impl SchnorrKeypair {
    /// Generate a key pair from secret scalar `sk`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::schnorr::SchnorrKeypair;
    /// let (pk, sk) = SchnorrKeypair::generate(7);
    /// assert_ne!(pk, 0);
    /// ```
    #[must_use]
    pub fn generate(sk: u64) -> (u64, u64) {
        (sk.wrapping_mul(G), sk)
    }
}

/// A Schnorr signature `(R, s)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchnorrSignature {
    /// Nonce commitment: `r * G`.
    pub r_point: u64,
    /// Response scalar: `r + e * sk`.
    pub s: u64,
}

/// Sign `message` with `(sk, pk)` using nonce `r`.
///
/// # Examples
///
/// ```rust
/// use miden_zk_primitives::schnorr::{SchnorrKeypair, sign, verify};
/// let (pk, sk) = SchnorrKeypair::generate(1);
/// let sig = sign(sk, pk, b"test", 2);
/// assert!(verify(pk, b"test", sig));
/// ```
#[must_use]
pub fn sign(sk: u64, pk: u64, message: &[u8], r: u64) -> SchnorrSignature {
    let msg_hash = hash_message(message);
    let r_point = r.wrapping_mul(G);
    let e = challenge_hash(r_point, pk, msg_hash);
    let s = r.wrapping_add(e.wrapping_mul(sk));
    SchnorrSignature { r_point, s }
}

/// Verify a Schnorr signature.
///
/// Checks `s * G == R + e * pk`.
///
/// # Examples
///
/// ```rust
/// use miden_zk_primitives::schnorr::{SchnorrKeypair, sign, verify};
/// let (pk, sk) = SchnorrKeypair::generate(5);
/// let sig = sign(sk, pk, b"data", 3);
/// assert!(verify(pk, b"data", sig));
/// assert!(!verify(pk, b"wrong", sig));
/// ```
#[must_use]
pub fn verify(pk: u64, message: &[u8], sig: SchnorrSignature) -> bool {
    let msg_hash = hash_message(message);
    let e = challenge_hash(sig.r_point, pk, msg_hash);
    let lhs = sig.s.wrapping_mul(G);
    let rhs = sig.r_point.wrapping_add(e.wrapping_mul(pk));
    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let (pk, sk) = SchnorrKeypair::generate(0xdead_beef);
        let sig = sign(sk, pk, b"hello miden", 0x1234);
        assert!(verify(pk, b"hello miden", sig));
    }

    #[test]
    fn verify_signature_ok_and_err() {
        let (pk, sk) = SchnorrKeypair::generate(77);
        let sig = sign(sk, pk, b"message", 88);
        assert!(verify(pk, b"message", sig));
        assert!(!verify(pk, b"different", sig));
    }

    #[test]
    fn wrong_pk_fails() {
        let (pk, sk) = SchnorrKeypair::generate(10);
        let (pk2, _) = SchnorrKeypair::generate(11);
        let sig = sign(sk, pk, b"test", 5);
        assert!(!verify(pk2, b"test", sig));
    }

    #[test]
    fn tampered_r_fails() {
        let (pk, sk) = SchnorrKeypair::generate(3);
        let mut sig = sign(sk, pk, b"abc", 4);
        sig.r_point ^= 1;
        assert!(!verify(pk, b"abc", sig));
    }
}
