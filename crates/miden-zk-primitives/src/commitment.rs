//! Pedersen-style commitment using Miden VM's built-in RPO hash permutation.
//!
//! # Protocol
//!
//! The commitment is `H(value ‖ randomness)` where `H` is the RPO-256
//! hash computed by the Miden `hperm` instruction.  The prover places
//! `value` and `randomness` onto the stack, calls `hperm`, and the
//! resulting top-of-stack words form the commitment.  The STARK proof
//! certifies that the prover knows the opening `(value, randomness)`.
//!
//! > **Note**: `hperm` absorbs a 12-element state (`[rate ‖ capacity]`).
//! > We pre-fill the first 10 elements with zeros and place our two
//! > secret values into the top two rate positions.

use crate::utils::{prove_program, verify_program, ProofBundle};

/// MASM program: push 10 zeros (hperm padding), apply the permutation.
/// Inputs are pushed last, so they sit at the top of the stack when
/// `hperm` reads them.
const COMMITMENT_SRC: &str = "
begin
    push.0.0.0.0.0.0.0.0.0.0
    hperm
end
";

/// Prove that you know `(value, randomness)` such that
/// `H(value ‖ randomness)` is the commitment.
pub fn prove_commit_open(value: u64, randomness: u64) -> Result<ProofBundle, String> {
    prove_program(COMMITMENT_SRC, &[randomness, value])
}

/// Verify the commitment opening proof.
pub fn verify_commit_open(
    value: u64,
    randomness: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    verify_program(COMMITMENT_SRC, &[randomness, value], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "generates a real STARK proof (~24 GB RAM); run locally with --ignored"]
    fn test_commit_open() {
        let b = prove_commit_open(42, 7).expect("prove failed");
        verify_commit_open(42, 7, &b).expect("verify failed");
    }
}
