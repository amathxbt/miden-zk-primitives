//! Schnorr-like signature verification inside Miden VM.
//!
//! Miden VM's STARK proof attests that:
//! - The verifier ran the full signature check program.
//! - The check passed (no `assert` was violated).
//!
//! ## Simplified protocol (educational)
//!
//! We use Miden VM's `hperm` to compute the challenge hash and
//! `u32` arithmetic for the scalar equation `s·G = R + e·pk`.
//! In the 32-bit group `G = 0x9e379b9` is the generator constant.

use crate::utils::{prove_program, verify_proof, ProofBundle};

/// Generator constant (32-bit safe for `u32` ops in Miden).
const G: u64 = 0x0757_4e4b; // a prime, fits in u32

/// MASM: verify Schnorr signature equation `s*G == R + e*pk`.
/// Public inputs: `[pk, R, e, s]`
const SCHNORR_VERIFY_MASM: &str = "
begin
    # Stack: [s, e, R, pk]  (top = s)
    # Compute s*G
    dup.0
    push.119181899   # G constant
    u32wrapping_mul  # s*G
    # Compute e*pk
    movup.1          # bring e to top: [e, s*G, R, pk]
    movup.3          # bring pk: [pk, e, s*G, R]
    u32wrapping_mul  # e*pk
    # Compute R + e*pk
    movup.2          # bring R: [R, e*pk, s*G]
    u32wrapping_add  # R + e*pk
    # Check s*G == R + e*pk
    movup.1          # [s*G, R+e*pk]
    assert_eq
    push.1
end
";

/// Prove that signature `(R, s)` is valid for public key `pk` and challenge `e`.
///
/// # Arguments
///
/// * `pk` — public key (secret_key * G mod 2^32)
/// * `r_point` — nonce commitment (r * G mod 2^32)
/// * `e` — challenge hash (H(R || pk || message))
/// * `s` — response scalar (r + e * sk)
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
        let msg_hash = 0xdeadc0de_u64 % (1u64 << 32);
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
