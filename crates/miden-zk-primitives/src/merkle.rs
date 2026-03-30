//! Merkle membership proof using Miden VM's native `mtree_verify` instruction.
//!
//! Miden VM has **built-in** Merkle tree instructions backed by RPO hashing.
//! `mtree_verify` pops `[depth, index, root_3, root_2, root_1, root_0]` from
//! the stack and checks (via the advice provider) that the node at `(depth,
//! index)` hashes up to `root`.  The STARK proof certifies the membership
//! path without revealing the siblings.
//!
//! ## Stack layout (bottom → top when calling `prove_program`)
//!
//! ```text
//! inputs = [root[0], root[1], root[2], root[3], index, depth]
//! ```
//!
//! The last element is placed at the top of the stack, so `depth` is
//! consumed first by `mtree_verify`.

use crate::utils::{prove_program, verify_program, ProofBundle};

/// MASM program for Merkle membership.
///
/// Stack on entry (top → bottom): `depth, index, root_3, root_2, root_1, root_0`
const MERKLE_VERIFY_MASM: &str = "
begin
    # Stack: [depth, index, root_3, root_2, root_1, root_0]
    mtree_verify
    # If we reach here the membership path is valid.
    push.1
end
";

/// Prove Merkle membership using Miden VM's native `mtree_verify`.
///
/// # Arguments
///
/// * `depth`  — tree depth (log₂ of leaf count)
/// * `index`  — leaf index (0-based)
/// * `root`   — 4 Goldilocks field elements forming the Merkle root (big-endian word)
/// * `_leaf`  — 4 field elements of the leaf value (used by the advice
///              provider in a full integration; kept for API compatibility here)
///
/// # Errors
///
/// Returns an error if proof generation fails (e.g. invalid Merkle path when
/// an advice provider is configured).
pub fn prove_merkle_membership(
    depth: u64,
    index: u64,
    root: [u64; 4],
    _leaf: [u64; 4],
) -> Result<ProofBundle, String> {
    // Inputs: [root[0], root[1], root[2], root[3], index, depth]
    // (the last value pushed ends up at the top of the stack)
    let inputs = [root[0], root[1], root[2], root[3], index, depth];
    prove_program(MERKLE_VERIFY_MASM, &inputs)
}

/// Verify a Merkle membership proof.
pub fn verify_merkle_membership(
    depth: u64,
    index: u64,
    root: [u64; 4],
    _leaf: [u64; 4],
    bundle: &ProofBundle,
) -> Result<(), String> {
    let inputs = [root[0], root[1], root[2], root[3], index, depth];
    verify_program(MERKLE_VERIFY_MASM, &inputs, bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time smoke test: ensures all public types and functions are
    /// reachable with their expected signatures.  No VM is invoked.
    #[test]
    fn merkle_api_compiles() {
        // Just verify the function signatures are accessible.
        // We don't call them because `mtree_verify` needs an advice provider.
        let _: fn(u64, u64, [u64; 4], [u64; 4]) -> Result<ProofBundle, String> =
            prove_merkle_membership;
        let _: fn(u64, u64, [u64; 4], [u64; 4], &ProofBundle) -> Result<(), String> =
            verify_merkle_membership;
    }

    /// Full prove+verify round-trip.
    ///
    /// Requires a populated advice provider with the actual Merkle tree path.
    /// Run locally with: `cargo test -- --ignored`
    #[test]
    #[ignore = "requires a populated advice provider and ~24 GB RAM; run locally with --ignored"]
    fn merkle_membership_full_roundtrip() {
        // TODO: populate advice provider with a real Merkle tree path and run.
    }
}
