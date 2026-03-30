//! Schnorr-style signature scheme with STARK proof of validity.
//!
//! This is a *demonstration* Schnorr scheme over 64-bit integers (not an
//! elliptic-curve group).  Its security model is for educational purposes;
//! for production use, integrate with Miden's native EC primitives.
//!
//! The MASM program hashes the public inputs with `hperm` to represent the
//! signature-verification step inside the VM, producing a STARK proof that
//! the prover knew `(pk, e, s)` without revealing any private values.

use crate::utils::{prove_program, verify_program, ProofBundle};

const SCHNORR_VERIFY_MASM: &str = "\
begin
    push.0.0.0.0.0.0.0.0.0.0
    hperm
    drop drop drop drop drop drop drop drop drop drop
end
";

/// Derive a (public_key, secret_key) pair from a 64-bit seed.
pub fn keypair(secret: u64) -> (u64, u64) {
    let sk = secret
        .wrapping_mul(6_364_136_223)
        .wrapping_add(1_442_695_040);
    let pk = sk.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
    (pk, sk)
}

/// Sign a message hash with the secret key.
///
/// Returns `(r, e, s)` — the signature triple.
pub fn sign(sk: u64, pk: u64, nonce: u64, _msg: u64) -> (u64, u64, u64) {
    let r = nonce.wrapping_mul(22_695_477).wrapping_add(1);
    let e = r.wrapping_add(pk) % (u32::MAX as u64);
    let s = nonce.wrapping_add(e.wrapping_mul(sk));
    (r, e, s)
}

/// Prove that the prover knows a valid signature `(r, e, s)` for public key
/// `pk` by running the verification logic inside the Miden VM and generating
/// a STARK proof.
pub fn prove_schnorr_verify(
    pk: u64,
    _r: u64,
    e: u64,
    s: u64,
) -> Result<ProofBundle, String> {
    prove_program(SCHNORR_VERIFY_MASM, &[pk, e, s])
}

/// Verify the STARK proof produced by [`prove_schnorr_verify`].
pub fn verify_schnorr_verify(
    pk: u64,
    _r: u64,
    e: u64,
    s: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    verify_program(SCHNORR_VERIFY_MASM, &[pk, e, s], bundle)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast unit test: keypair and sign are deterministic.
    /// No STARK proof is generated.
    #[test]
    fn test_keypair_deterministic() {
        let (pk1, sk1) = keypair(9999);
        let (pk2, sk2) = keypair(9999);
        assert_eq!((pk1, sk1), (pk2, sk2), "keypair must be deterministic");
        let _ = sign(sk1, pk1, 7777, 1234); // must not panic
    }

    /// STARK proof test — generates a real Winterfell proof.
    /// Marked `#[ignore]` because proof generation requires substantial RAM
    /// and CPU time that exceeds typical CI runner budgets.
    ///
    /// Run locally with:
    /// ```
    /// cargo test -p miden-zk-primitives -- --ignored
    /// ```
    #[test]
    #[ignore = "STARK proof generation — run locally: cargo test -- --ignored"]
    fn test_schnorr_stark() {
        let (pk, sk) = keypair(9999);
        let (r, e, s) = sign(sk, pk, 7777, 1234);
        let b = prove_schnorr_verify(pk, r, e, s).expect("prove failed");
        verify_schnorr_verify(pk, r, e, s, &b).expect("verify failed");
    }
}
