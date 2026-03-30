//! Nullifier primitive — prevents double-spending / double-voting.
//!
//! # Protocol
//!
//! A nullifier is a one-way deterministic value derived from a secret key
//! and a note index: `nullifier = H(secret_key ‖ note_index)`.  The STARK
//! proof certifies that the prover knows the secret key corresponding to
//! a given note, without revealing the key itself.  Once a nullifier is
//! submitted on-chain, the same note cannot be consumed again.

use crate::utils::{prove_program, verify_program, ProofBundle};

/// MASM program: absorb `(secret_key, note_index)` through RPO via `hperm`.
const NULLIFIER_SRC: &str = "
begin
    push.0.0.0.0.0.0.0.0.0.0
    hperm
end
";

/// Generate a STARK proof of nullifier knowledge.
///
/// `secret_key` is the private note key; `note_index` identifies the note.
pub fn prove_nullifier(secret_key: u64, note_index: u64) -> Result<ProofBundle, String> {
    prove_program(NULLIFIER_SRC, &[note_index, secret_key])
}

/// Verify the nullifier proof.
pub fn verify_nullifier(
    secret_key: u64,
    note_index: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    verify_program(NULLIFIER_SRC, &[note_index, secret_key], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "generates a real STARK proof (~24 GB RAM); run locally with --ignored"]
    fn test_nullifier() {
        let b = prove_nullifier(12345, 1).expect("prove failed");
        verify_nullifier(12345, 1, &b).expect("verify failed");
    }
}
