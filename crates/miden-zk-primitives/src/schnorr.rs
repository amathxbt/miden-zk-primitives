//! Schnorr-like signature verification inside Miden VM.
//!
//! Miden VM's STARK proof attests that:
//! - The verifier ran the full signature check program.
//! - The check passed (no `assert` was violated).
//!
//! ## Simplified protocol (educational)
//!
//! We use a lightweight challenge hash and `u32` arithmetic for the scalar
//! equation `s·G = R + e·pk`.  In this 32-bit group `G = 0x07574e4b`
//! (a small prime that fits comfortably in `u32`).

use crate::utils::{prove_program, verify_proof, ProofBundle};

/// Generator constant (32-bit safe for `u32` ops in Miden).
const G: u64 = 0x0757_4e4b; // fits in u32

/// MASM: verify Schnorr equation `s*G == R + e*pk`.
///
/// Public inputs (bottom → top): `[pk, R, e, s]`
///
/// Stack trace (top shown first):
/// ```text
/// [s, e, R, pk]
/// push G → mul          → [s*G, e, R, pk]
/// swap                  → [e, s*G, R, pk]
/// movup.3               → [pk, e, s*G, R]
/// mul e*pk              → [e*pk, s*G, R]
/// movup.2               → [R, e*pk, s*G]
/// add R+e*pk            → [R+e*pk, s*G]
/// swap                  → [s*G, R+e*pk]
/// assert_eq             → []   (or trap)
/// push.1                → [1]
/// ```
const SCHNORR_VERIFY_MASM: &str = "
begin
    # Stack: [s, e, R, pk]  (top = s)
    # Compute s*G  (push G then multiply — no dup needed)
    push.119181899       # G constant  [G, s, e, R, pk]
    u32wrapping_mul      # [s*G, e, R, pk]
    # Bring e to top, then pk, multiply to get e*pk
    swap                 # [e, s*G, R, pk]
    movup.3              # [pk, e, s*G, R]
    u32wrapping_mul      # [e*pk, s*G, R]
    # Bring R to top and add
    movup.2              # [R, e*pk, s*G]
    u32wrapping_add      # [R+e*pk, s*G]
    # Compare s*G == R+e*pk
    swap                 # [s*G, R+e*pk]
    assert_eq
    push.1
end
";

/// Prove that signature `(R, s)` is valid for public key `pk` and challenge `e`.
///
/// # Arguments
///
/// * `pk`      — public key (secret_key * G mod 2^32)
/// * `r_point` — nonce commitment (r * G mod 2^32)
/// * `e`       — challenge hash (H(R || pk || message))
/// * `s`       — response scalar (r + e * sk mod 2^32)
///
/// # Errors
///
/// Returns an error if the signature equation fails inside the VM.
pub fn prove_schnorr_verify(pk: u64, r_point: u64, e: u64, s: u64) -> Result<ProofBundle, String> {
    prove_program(SCHNORR_VERIFY_MASM, &[pk, r_point, e, s])
}

/// Verify the Schnorr verification proof.
pub fn verify_schnorr_verify(
    pk: u64,
    r_point: u64,
    e: u64,
    s: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    verify_proof(SCHNORR_VERIFY_MASM, &[pk, r_point, e, s], bundle)
}

/// Compute a Schnorr key pair from `sk`.
pub fn keypair(sk: u64) -> (u64, u64) {
    let pk = (sk as u128 * G as u128 % (1u128 << 32)) as u64;
    (pk, sk)
}

/// Sign a pre-hashed message `msg_hash` with `(sk, pk)` and nonce `r`.
pub fn sign(sk: u64, pk: u64, r: u64, msg_hash: u64) -> (u64, u64, u64) {
    let r_point = (r as u128 * G as u128 % (1u128 << 32)) as u64;
    let e = challenge_hash(r_point, pk, msg_hash);
    let s = (r as u128 + e as u128 * sk as u128) as u64 % (1u64 << 32);
    (r_point, e, s)
}

/// Challenge hash: H(R || pk || msg).
pub fn challenge_hash(r: u64, pk: u64, msg: u64) -> u64 {
    let x = r
        .wrapping_mul(0x6c62_272e)
        .wrapping_add(pk)
        .wrapping_add(msg);
    (x ^ (x >> 17)) % (1u64 << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schnorr_sign_and_prove() {
        let (pk, sk) = keypair(12345);
        let msg_hash = 0xdeadc0de_u64;
        let (r_point, e, s) = sign(sk, pk, 99999, msg_hash);
        let bundle = prove_schnorr_verify(pk, r_point, e, s).expect("prove failed");
        verify_schnorr_verify(pk, r_point, e, s, &bundle).expect("verify failed");
    }

    #[test]
    fn wrong_signature_fails() {
        let (pk, sk) = keypair(1);
        let (r_point, e, s) = sign(sk, pk, 2, 3);
        let bundle = prove_schnorr_verify(pk, r_point, e, s).unwrap();
        // tamper: use wrong s+1
        assert!(verify_schnorr_verify(pk, r_point, e, s + 1, &bundle).is_err());
    }
}
