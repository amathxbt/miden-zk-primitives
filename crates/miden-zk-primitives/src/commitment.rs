//! Pedersen-style commitment using Miden VM's native RPO hash.
//!
//! The commitment is computed **inside the Miden VM** using the `hperm`
//! instruction (Rescue Prime Optimized — the native hash of Miden VM).
//! The prover receives a STARK proof that the commitment was computed honestly.
//!
//! ## How it works
//!
//! 1. Push `[value, randomness, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]` onto the stack
//! 2. Apply `hperm` (one full RPO permutation — 7 rounds)  
//! 3. Drop the rate words, keep the capacity (the commitment)
//!
//! The MASM program:
//! - Takes `(value, randomness)` as public inputs
//! - Outputs the 4-word commitment on the stack
//! - The proof attests the computation was done honestly

use crate::utils::{prove_program, verify_proof, ProofBundle};

/// MASM program: hash `[value || randomness || padding]` with `hperm`.
const COMMIT_MASM: &str = "
begin
    # Stack: [value, randomness]
    # Pad to 12 elements for hperm (rate=8, capacity=4)
    push.0 push.0 push.0 push.0   # 4 capacity words
    push.0 push.0 push.0 push.0   # 4 rate padding words
    # value and randomness are already on the stack
    # Stack layout (bottom→top): [capacity×4, padding×4, randomness, value]
    hperm
    # hperm outputs 12 words; top 4 are the hash (capacity out)
    # drop rate output (8 words), keep capacity (4 words = commitment)
    movdn.3 movdn.3 movdn.3 movdn.3   # move capacity below rate
    drop drop drop drop drop drop drop drop   # drop the 8 rate words
    # Stack: [c3, c2, c1, c0]  (the 4-word commitment)
end
";

/// Prove that `commit(value, randomness)` was computed honestly.
///
/// Returns a [`ProofBundle`] containing:
/// - The 4-word RPO commitment as `outputs[0..4]`
/// - The STARK proof bytes
///
/// # Errors
///
/// Returns an error string if the Miden VM fails to compile or prove.
///
/// # Example
///
/// ```rust,no_run
/// use miden_zk_primitives::commitment::prove_commit_open;
/// let bundle = prove_commit_open(42, 7).unwrap();
/// assert_eq!(bundle.outputs.len(), 16); // full stack
/// ```
pub fn prove_commit_open(value: u64, randomness: u64) -> Result<ProofBundle, String> {
    prove_program(COMMIT_MASM, &[randomness, value])
}

/// Verify the commitment proof produced by [`prove_commit_open`].
///
/// # Errors
///
/// Returns an error string if the STARK proof is invalid.
pub fn verify_commit_open(value: u64, randomness: u64, bundle: &ProofBundle) -> Result<(), String> {
    verify_proof(COMMIT_MASM, &[randomness, value], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_prove_and_verify() {
        let bundle = prove_commit_open(42, 99).expect("prove failed");
        verify_commit_open(42, 99, &bundle).expect("verify failed");
    }

    #[test]
    fn different_values_different_commitments() {
        let b1 = prove_commit_open(1, 10).unwrap();
        let b2 = prove_commit_open(2, 10).unwrap();
        assert_ne!(b1.outputs[0], b2.outputs[0], "commitments must differ");
    }

    #[test]
    fn wrong_value_fails_verify() {
        let bundle = prove_commit_open(42, 99).unwrap();
        // verifying with wrong value should fail (hash mismatch → stack output differs)
        let result = verify_commit_open(43, 99, &bundle);
        assert!(result.is_err(), "wrong value should fail verification");
    }
}
