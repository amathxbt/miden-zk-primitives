//! RSA-style accumulator built entirely on Miden VM u32 arithmetic.
//!
//! # Arithmetic contract
//!
//! The MASM program uses `u32wrapping_mul`, which computes
//! `(a * b) mod 2³²`.  The Rust side therefore mirrors this with
//! `u32` saturated/wrapping arithmetic so both sides agree.
//!
//! Elements are mapped to "factors" with `factor = (element as u32)
//! .wrapping_add(31337)` before being multiplied into the accumulator.
//! This ensures even small inputs (0, 1, …) produce distinct factors.

use crate::utils::{prove_program, verify_program, ProofBundle};

// ── MASM template ────────────────────────────────────────────────────────────

/// Returns the MASM program that checks: `witness * factor == accumulator (mod 2³²)`.
///
/// All three values must be valid u32 values (< 2³²) when pushed.
fn acc_src(witness: u32, factor: u32, accumulator: u32) -> String {
    format!(
        "begin\n    \
         push.{witness}\n    \
         push.{factor}\n    \
         u32wrapping_mul\n    \
         push.{accumulator}\n    \
         assert_eq\n\
         end"
    )
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Build the accumulator value from a slice of elements.
///
/// Uses `u32` wrapping multiplication to stay in sync with the MASM program.
pub fn build_accumulator(elements: &[u64]) -> u64 {
    elements
        .iter()
        .fold(1u32, |acc, &e| {
            let factor = (e as u32).wrapping_add(31337);
            acc.wrapping_mul(factor)
        }) as u64
}

/// Compute the membership witness for `target` in `elements`.
///
/// Returns `None` if `target` is not in `elements`.
pub fn compute_witness(elements: &[u64], target: u64) -> Option<u64> {
    if !elements.contains(&target) {
        return None;
    }
    Some(
        elements
            .iter()
            .filter(|&&e| e != target)
            .fold(1u32, |acc, &e| {
                let factor = (e as u32).wrapping_add(31337);
                acc.wrapping_mul(factor)
            }) as u64,
    )
}

/// Returns the factor for `element` (i.e. `(element as u32) + 31337`).
///
/// Exposed so callers can inspect or log the factor without recomputing it.
pub fn element_factor(element: u64) -> u64 {
    (element as u32).wrapping_add(31337) as u64
}

/// Generate a STARK membership proof: proves that `witness * (element + 31337) == accumulator`
/// under `u32` wrapping arithmetic.
pub fn prove_membership(
    accumulator: u64,
    element: u64,
    witness: u64,
) -> Result<ProofBundle, String> {
    let acc32 = accumulator as u32;
    let factor32 = (element as u32).wrapping_add(31337);
    let witness32 = witness as u32;
    prove_program(&acc_src(witness32, factor32, acc32), &[])
}

/// Verify a STARK membership proof.
pub fn verify_membership(
    accumulator: u64,
    element: u64,
    witness: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    let acc32 = accumulator as u32;
    let factor32 = (element as u32).wrapping_add(31337);
    let witness32 = witness as u32;
    verify_program(&acc_src(witness32, factor32, acc32), &[], bundle)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `build_accumulator` and `compute_witness` produce values
    /// that are consistent with each other (Rust-side only — no VM needed).
    #[test]
    fn test_accumulator_consistency() {
        let elems = vec![100u64, 200, 300];
        let acc = build_accumulator(&elems);
        let w = compute_witness(&elems, 200).unwrap();
        // The product `w * factor(200)` must equal `acc` under u32 wrapping.
        let factor = element_factor(200) as u32;
        let recomputed = (w as u32).wrapping_mul(factor) as u64;
        assert_eq!(recomputed, acc, "witness * factor should equal accumulator");
    }

    /// Non-member should return None.
    #[test]
    fn test_non_member_returns_none() {
        let elems = vec![1u64, 2, 3];
        assert!(compute_witness(&elems, 999).is_none());
    }

    /// Full prove+verify round-trip using small values that keep all
    /// intermediate products < 2³².
    ///
    /// Uses element 5 with set {5, 7, 11} — chosen so that
    /// witness = factor(7) * factor(11) = 31344 * 31348 < 2³².
    #[test]
    #[ignore = "generates a real STARK proof (~24 GB RAM); run locally with --ignored"]
    fn test_membership_prove_verify() {
        let elems = vec![5u64, 7, 11];
        let acc = build_accumulator(&elems);
        let w = compute_witness(&elems, 5).unwrap();
        let b = prove_membership(acc, 5, w).expect("prove failed");
        verify_membership(acc, 5, w, &b).expect("verify failed");
    }
}
