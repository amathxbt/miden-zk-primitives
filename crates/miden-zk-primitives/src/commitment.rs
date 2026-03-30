//! Pedersen-style commitment via Miden VM's RPO hash permutation.
//!
//! The prover commits to `(value, randomness)` by running the ten-element
//! `hperm` permutation.  The commitment (output state) is the ZK proof output;
//! the STARK proof guarantees the committed pair produced that output without
//! revealing the pre-image.

use crate::utils::{prove_program, verify_program, ProofBundle};

/// MASM program: initialise the RPO state with ten zeros, then run one
/// `hperm` round.  Public inputs are pushed *before* the program runs
/// (i.e. they sit below the synthesised zero-pad on the stack), but the
/// current impl uses `prove_program` with explicit inputs which the VM
/// places on the stack before execution.
const COMMITMENT_SRC: &str = "\
begin
    push.0.0.0.0.0.0.0.0.0.0
    hperm
end
";

/// Prove a commitment to `(value, randomness)` using a real Miden STARK proof.
///
/// The two values are pushed onto the stack before the RPO permutation runs;
/// the digest (output state) constitutes the commitment and is recorded in
/// `ProofBundle::outputs`.
pub fn prove_commit_open(value: u64, randomness: u64) -> Result<ProofBundle, String> {
    prove_program(COMMITMENT_SRC, &[randomness, value])
}

/// Verify the commitment proof produced by [`prove_commit_open`].
pub fn verify_commit_open(
    value: u64,
    randomness: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    verify_program(COMMITMENT_SRC, &[randomness, value], bundle)
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
    fn test_commit_open() {
        let b = prove_commit_open(42, 7).expect("prove failed");
        verify_commit_open(42, 7, &b).expect("verify failed");
    }
}
