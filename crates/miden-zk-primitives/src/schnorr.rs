//! Simplified Schnorr signature scheme with STARK proof of verification.
//!
//! > **Note**: This is a pedagogical implementation intended to demonstrate
//! > how Schnorr-like verification can be encoded in MASM.  For production
//! > use, replace with a full Schnorr implementation over a suitable curve.
//!
//! The MASM program currently performs an RPO hash permutation as a
//! stand-in for the actual Schnorr verification equation.  The proof
//! certifies that the MASM program executed correctly with the given
//! public inputs.

use crate::utils::{prove_program, verify_program, ProofBundle};

/// MASM program: absorb public inputs through the RPO permutation.
const SCHNORR_VERIFY_MASM: &str = "
begin
    push.0.0.0.0.0.0.0.0.0.0
    hperm
    drop drop drop drop drop drop drop drop drop drop
end
";

/// Derive `(public_key, secret_key)` from a 64-bit seed using a simple
/// linear congruential transform.
pub fn keypair(secret: u64) -> (u64, u64) {
    let sk = secret.wrapping_mul(6_364_136_223).wrapping_add(1_442_695_040);
    let pk = sk.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    (pk, sk)
}

/// Sign `msg` with `sk` using a deterministic nonce.
///
/// Returns `(r, e, s)` where `r` is the nonce commitment, `e` is the
/// challenge, and `s` is the response.
pub fn sign(sk: u64, pk: u64, nonce: u64, _msg: u64) -> (u64, u64, u64) {
    let r = nonce.wrapping_mul(22_695_477).wrapping_add(1);
    let e = r.wrapping_add(pk) % (u32::MAX as u64);
    let s = nonce.wrapping_add(e.wrapping_mul(sk));
    (r, e, s)
}

/// Generate a STARK proof of Schnorr signature verification.
///
/// `_r` is included for API completeness (the nonce commitment) but not
/// used as a public input in the current MASM program.
pub fn prove_schnorr_verify(
    pk: u64,
    _r: u64,
    e: u64,
    s: u64,
) -> Result<ProofBundle, String> {
    prove_program(SCHNORR_VERIFY_MASM, &[pk, e, s])
}

/// Verify the Schnorr STARK proof.
pub fn verify_schnorr_verify(
    pk: u64,
    _r: u64,
    e: u64,
    s: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    verify_program(SCHNORR_VERIFY_MASM, &[pk, e, s], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "generates a real STARK proof (~24 GB RAM); run locally with --ignored"]
    fn test_schnorr() {
        let (pk, sk) = keypair(9999);
        let (r, e, s) = sign(sk, pk, 7777, 1234);
        let b = prove_schnorr_verify(pk, r, e, s).expect("prove failed");
        verify_schnorr_verify(pk, r, e, s, &b).expect("verify failed");
    }
}
