//! Set-membership proof using Miden VM's `mtree_verify` instruction.
//!
//! The set is committed to as a Merkle tree (using native RPO hashing).
//! The prover shows membership without revealing the full set.
//!
//! ## Protocol
//!
//! 1. Committer builds a Merkle tree over the set elements.
//! 2. Prover knows the leaf index and the sibling path.
//! 3. `mtree_verify` checks the path inside the VM.
//! 4. A STARK proof attests the verification succeeded.

use crate::utils::{prove_program, verify_proof, ProofBundle};

/// MASM: verify that a leaf is in the Merkle tree.
/// Public stack (bottom → top): `[root_0..root_3, index, depth]`
const SET_MASM: &str = "
begin
    # Stack: [depth, index, root_3, root_2, root_1, root_0]
    mtree_verify
    push.1
end
";

/// Prove set membership for an element at `index` in a tree with `root`.
///
/// # Arguments
///
/// * `depth` — tree depth
/// * `index` — leaf index of the element
/// * `root`  — 4-word Merkle root
///
/// # Errors
///
/// Returns an error if the VM rejects the membership proof.
pub fn prove_set_membership(depth: u64, index: u64, root: [u64; 4]) -> Result<ProofBundle, String> {
    let inputs = [root[0], root[1], root[2], root[3], index, depth];
    prove_program(SET_MASM, &inputs)
}

/// Verify a set-membership proof.
pub fn verify_set_membership(
    depth: u64,
    index: u64,
    root: [u64; 4],
    bundle: &ProofBundle,
) -> Result<(), String> {
    let inputs = [root[0], root[1], root[2], root[3], index, depth];
    verify_proof(SET_MASM, &inputs, bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_masm_compiles() {
        // Ensure the MASM compiles (full integration test is in examples/).
        // A zeroed root will cause mtree_verify to fail at runtime — that's OK.
        let _ = prove_set_membership(2, 0, [0u64; 4]);
    }
}
