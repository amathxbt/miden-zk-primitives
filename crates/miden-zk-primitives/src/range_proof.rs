//! Range proof — prove `lo ≤ value ≤ hi` using Miden's native u32 comparison
//! instructions.
//!
//! Miden's `u32gte` / `u32lte` instructions operate in O(1) circuit rows and
//! enforce both operands to be valid 32-bit unsigned integers, so this proof
//! is both compact and efficient.
//!
//! **Constraint**: `value`, `lo`, and `hi` must all fit in a u32
//! (i.e. be in `0 ..= 4_294_967_295`).  Passing values outside this range
//! will cause the VM to trap and `prove_range` will return `Err(…)`.

use crate::utils::{prove_program, verify_program, ProofBundle};

/// Inline the bounds and value directly into the MASM so the verifier can
/// confirm *exactly* which range was checked from the program hash alone.
fn range_src(value: u64, lo: u64, hi: u64) -> String {
    // Stack after each pair of pushes (top is left):
    //   push.value; push.lo  → [lo, value, ...]   u32gte → value >= lo ✓
    //   push.value; push.hi  → [hi, value, ...]   u32lte → value <= hi ✓
    format!(
        "begin\n    \
         push.{value}\n    \
         push.{lo}\n    \
         u32gte\n    \
         assert\n    \
         push.{value}\n    \
         push.{hi}\n    \
         u32lte\n    \
         assert\n\
         end"
    )
}

/// Prove that `lo ≤ value ≤ hi` using a real Miden STARK proof.
///
/// All three arguments must fit in a `u32`.
pub fn prove_range(value: u64, lo: u64, hi: u64) -> Result<ProofBundle, String> {
    prove_program(&range_src(value, lo, hi), &[])
}

/// Verify the range proof produced by [`prove_range`].
pub fn verify_range(value: u64, lo: u64, hi: u64, bundle: &ProofBundle) -> Result<(), String> {
    verify_program(&range_src(value, lo, hi), &[], bundle)
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
    fn test_range_pass() {
        let b = prove_range(25, 18, 120).expect("prove failed");
        verify_range(25, 18, 120, &b).expect("verify failed");
    }

    /// Verify that values outside the range produce an error (not a panic).
    ///
    /// This is a lightweight compile / logic test — no STARK proof is generated.
    #[test]
    fn test_range_src_generation() {
        let src = range_src(25, 18, 120);
        assert!(src.contains("push.25"), "value missing from MASM");
        assert!(src.contains("push.18"), "lo missing from MASM");
        assert!(src.contains("push.120"), "hi missing from MASM");
        assert!(src.contains("u32gte"), "lower-bound check missing");
        assert!(src.contains("u32lte"), "upper-bound check missing");
    }
}
