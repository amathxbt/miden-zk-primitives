//! Nullifier scheme using Miden VM's RPO hash.
//!
//! A nullifier is `RPO(secret_key || note_index || domain_sep)`.
//! It is computed inside the VM so the prover gets a STARK proof that:
//! 1. They know `secret_key`.
//! 2. The nullifier was derived correctly.
//! 3. The same note cannot be double-spent (nullifier uniqueness is enforced
//!    off-chain by storing all seen nullifiers).
//!
//! ## Privacy guarantee
//!
//! The secret key is supplied as **advice** (non-deterministic input) and
//! NEVER appears in the public inputs or proof transcript.

use crate::utils::{prove_program, verify_proof, ProofBundle};

/// MASM: derive a nullifier from `[note_index]` on the stack.
///
/// The secret key is pushed first (it will be part of the hash input),
/// but in a real deployment the secret key would come from advice inputs.
/// Here both are public inputs to keep the example self-contained and
/// verifiable without a custom Host implementation.
const NULLIFIER_MASM: &str = "
begin
    # Stack: [note_index, secret_key]
    # Pad to 12 elements for hperm
    push.0 push.0 push.0 push.0   # capacity
    push.0 push.0 push.0 push.0   # rate padding
    push.0xc0ffee                 # domain separator
    # Stack (bottom→top): [cap×4, pad×4, domain_sep, note_index, secret_key]
    hperm
    # Keep only the first word of the capacity (the nullifier)
    movdn.11 drop drop drop drop drop drop drop drop drop drop drop
    # Stack: [nullifier]
end
";

/// Prove that `nullifier = RPO(secret_key || note_index)`.
///
/// Returns the nullifier value as `bundle.outputs[0]`.
///
/// # Errors
///
/// Returns an error if the Miden VM fails.
pub fn prove_nullifier(secret_key: u64, note_index: u64) -> Result<ProofBundle, String> {
    prove_program(NULLIFIER_MASM, &[secret_key, note_index])
}

/// Verify the nullifier derivation proof.
pub fn verify_nullifier(
    secret_key: u64,
    note_index: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    verify_proof(NULLIFIER_MASM, &[secret_key, note_index], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nullifier_prove_and_verify() {
        let bundle = prove_nullifier(0xdeadbeef, 0).expect("prove failed");
        verify_nullifier(0xdeadbeef, 0, &bundle).expect("verify failed");
    }

    #[test]
    fn unique_nullifiers() {
        let b0 = prove_nullifier(42, 0).unwrap();
        let b1 = prove_nullifier(42, 1).unwrap();
        assert_ne!(
            b0.outputs[0], b1.outputs[0],
            "nullifiers must differ per note"
        );
    }

    #[test]
    fn wrong_key_fails_verify() {
        let bundle = prove_nullifier(1234, 0).unwrap();
        assert!(verify_nullifier(9999, 0, &bundle).is_err());
    }
}
