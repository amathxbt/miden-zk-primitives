//! Nullifier primitive — prevents double-spending / double-voting.
//!
//! A nullifier is a deterministic, collision-resistant value derived from a
//! `(secret_key, note_index)` pair.  Two proofs for the same `(sk, idx)` will
//! produce the same nullifier value, so a ledger can detect duplicates without
//! ever learning the secret key.
//!
//! This implementation derives the nullifier by running the RPO `hperm`
//! permutation over the inputs inside the Miden VM and generating a STARK
//! proof of correct derivation.

use crate::utils::{prove_program, verify_program, ProofBundle};

const NULLIFIER_SRC: &str = "\
begin
    push.0.0.0.0.0.0.0.0.0.0
    hperm
end
";

/// Prove that `nullifier = RPO(secret_key, note_index)` using a STARK proof.
///
/// The nullifier value itself is the first element of `ProofBundle::outputs`.
pub fn prove_nullifier(secret_key: u64, note_index: u64) -> Result<ProofBundle, String> {
    prove_program(NULLIFIER_SRC, &[note_index, secret_key])
}

/// Verify the nullifier proof produced by [`prove_nullifier`].
pub fn verify_nullifier(
    secret_key: u64,
    note_index: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    verify_program(NULLIFIER_SRC, &[note_index, secret_key], bundle)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_nullifier() {
        let b = prove_nullifier(12345, 1).expect("prove failed");
        verify_nullifier(12345, 1, &b).expect("verify failed");
    }
}
