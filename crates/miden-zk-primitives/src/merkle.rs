//! Merkle membership proof using Miden VM's native `mtree_verify` instruction.
//!
//! Miden VM has **built-in** Merkle tree instructions that use RPO hashing.
//! `mtree_verify` proves membership in O(log n) without revealing the full tree.
//!
//! ## Stack layout for `mtree_verify`
//!
//! ```text
//! mtree_verify
//! # Consumes: [depth, index, root_3, root_2, root_1, root_0, ...]
//! # The Merkle path (sibling hashes) is supplied as *advice* inputs —
//! # non-deterministic secrets that are NOT in the public inputs but ARE
//! # verified by the STARK proof.
//! ```
//!
//! ## Limitations in this crate
//!
//! Full Merkle proofs require loading the tree into the VM's advice provider.
//! This crate's `prove_program` helper uses `DefaultHost`, which does not
//! pre-populate the advice Merkle store.  `prove_merkle_membership` therefore
//! succeeds only when the tree data happens to be trivially checkable (e.g.,
//! a single-leaf tree with all-zero root).  For production use, supply a
//! custom `Host` with the Merkle tree pre-loaded.

use crate::utils::{prove_program, verify_program, ProofBundle};

/// MASM: verify a Merkle membership proof.
///
/// Public inputs (stack, bottom → top when passed to `prove_program`):
/// `[root_0, root_1, root_2, root_3, index, depth]`
const MERKLE_VERIFY_MASM: &str = "\
begin
    # Stack (top first): [depth, index, root_3, root_2, root_1, root_0]
    mtree_verify
    # Reaching here means membership is valid.
    push.1
end
";

/// Prove Merkle membership using Miden VM's native `mtree_verify`.
///
/// # Arguments
///
/// * `depth`  — tree depth (number of levels above the leaf)
/// * `index`  — leaf index
/// * `root`   — four Goldilocks field elements forming the Merkle root
/// * `_leaf`  — four field elements of the leaf value (used by advice provider
///   in production; kept as a parameter for API compatibility)
///
/// # Note
///
/// This function will return an error when called without a populated advice
/// provider (the default for this crate).  Full integration requires
/// constructing a `MerkleStore`-backed host; see the crate README.
pub fn prove_merkle_membership(
    depth: u64,
    index: u64,
    root: [u64; 4],
    _leaf: [u64; 4],
) -> Result<ProofBundle, String> {
    // Stack inputs are consumed in *reverse* order: the last element becomes
    // the top of the stack.  We want: top = depth, then index, then root[3..0].
    let inputs = [root[0], root[1], root[2], root[3], index, depth];
    prove_program(MERKLE_VERIFY_MASM, &inputs)
}

/// Verify the Merkle membership proof.
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

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: the MASM assembles and the public API is reachable.
    ///
    /// With a zeroed root and no advice provider the VM is expected to fail at
    /// runtime — that is intentional.  What matters here is that the code
    /// *compiles* and the function *returns* rather than panicking.
    #[test]
    fn test_merkle_compiles_and_returns() {
        // Either Ok or Err is acceptable here; panic is not.
        let _ = prove_merkle_membership(2, 0, [0u64; 4], [0u64; 4]);
    }

    /// Full STARK proof test — requires a populated MerkleStore advice provider.
    /// Marked `#[ignore]` for CI.
    ///
    /// Run locally with:
    /// ```
    /// cargo test -p miden-zk-primitives -- --ignored
    /// ```
    #[test]
    #[ignore = "STARK proof generation — run locally: cargo test -- --ignored"]
    fn test_merkle_membership_stark() {
        // This would need a custom Host with a Merkle tree pre-loaded.
        // See examples/ for a full integration demo.
        todo!("integrate with MerkleStore-backed Host");
    }
}
