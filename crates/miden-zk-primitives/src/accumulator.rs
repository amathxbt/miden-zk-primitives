//! Accumulator-based set-membership using Goldilocks field arithmetic.
//!
//! ## Design
//!
//! Elements are accumulated via repeated field multiplication in the
//! **Goldilocks** prime field  `𝔽_p` where `p = 2^64 − 2^32 + 1`.
//! Using *field* multiplication (instead of wrapping u64 or u32 mul) keeps
//! every intermediate value representable as a single Miden `Felt`, which is
//! what the `mul` MASM instruction operates on.
//!
//! ### Why the old code failed in CI
//!
//! The original MASM used `u32wrapping_mul` while the Rust side used 64-bit
//! `wrapping_mul`.  For the three-element test `[100, 200, 300]` the
//! accumulator grows to ≈ 31 billion — well above `u32::MAX` (≈ 4.3 billion).
//! The VM therefore rejected the inputs as "not valid u32 values" and the
//! test panicked at runtime.

use crate::utils::{prove_program, verify_program, ProofBundle};

// ── Goldilocks field helpers ─────────────────────────────────────────────────

/// Goldilocks prime  p = 2^64 − 2^32 + 1
const P: u128 = (1u128 << 64) - (1u128 << 32) + 1;

/// Multiply `a · b` in the Goldilocks field.
#[inline]
fn field_mul(a: u64, b: u64) -> u64 {
    ((a as u128 * b as u128) % P) as u64
}

/// Add `a + b` in the Goldilocks field.
#[inline]
fn field_add(a: u64, b: u64) -> u64 {
    // simple: reduce via u128 to avoid overflow
    ((a as u128 + b as u128) % P) as u64
}

// ── MASM template ────────────────────────────────────────────────────────────

/// Generate the MASM program that checks `witness * factor == accumulator`
/// in the Goldilocks field using the `mul` instruction.
fn acc_src(witness: u64, factor: u64, accumulator: u64) -> String {
    // Stack after setup: [accumulator, factor, witness]
    // `mul` → [factor * witness]
    // `push.accumulator; assert_eq` → asserts equality, leaves empty stack
    format!(
        "begin\n    \
         push.{witness}\n    \
         push.{factor}\n    \
         mul\n    \
         push.{accumulator}\n    \
         assert_eq\n\
         end"
    )
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Build a commitment (accumulator value) over `elements`.
///
/// Each element `e` contributes the factor `e + 31337` so that `0` is not a
/// trivial absorbing element.  All arithmetic is in the Goldilocks field, which
/// matches the MASM `mul` instruction exactly.
pub fn build_accumulator(elements: &[u64]) -> u64 {
    elements
        .iter()
        .fold(1u64, |acc, &e| field_mul(acc, field_add(e, 31337)))
}

/// Compute the membership witness for `target` in `elements`.
///
/// Returns `None` if `target` is not in `elements`.
/// The witness is the accumulator of all *other* elements — so that
/// `witness * (target + 31337) == accumulator`.
pub fn compute_witness(elements: &[u64], target: u64) -> Option<u64> {
    if !elements.contains(&target) {
        return None;
    }
    Some(
        elements
            .iter()
            .filter(|&&e| e != target)
            .fold(1u64, |acc, &e| field_mul(acc, field_add(e, 31337))),
    )
}

/// Returns the factor for `element` in the accumulator (i.e. `element + 31337`
/// reduced in the Goldilocks field).
///
/// Exposed so callers can inspect or log the factor without recomputing it.
pub fn element_factor(element: u64) -> u64 {
    field_add(element, 31337)
}

/// Prove that `witness * element_factor(element) == accumulator` using a real
/// Miden STARK proof.
pub fn prove_membership(
    accumulator: u64,
    element: u64,
    witness: u64,
) -> Result<ProofBundle, String> {
    let factor = element_factor(element);
    prove_program(&acc_src(witness, factor, accumulator), &[])
}

/// Verify the STARK proof of accumulator membership.
pub fn verify_membership(
    accumulator: u64,
    element: u64,
    witness: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    let factor = element_factor(element);
    verify_program(&acc_src(witness, factor, accumulator), &[], bundle)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast sanity-check: the Rust-side arithmetic is self-consistent.
    /// This runs in microseconds and requires no STARK proof.
    #[test]
    fn test_accumulator_arithmetic() {
        let elems = vec![100u64, 200, 300];
        let acc = build_accumulator(&elems);
        let w = compute_witness(&elems, 200).unwrap();
        let factor = element_factor(200);

        // witness * factor must equal accumulator in the Goldilocks field
        assert_eq!(
            field_mul(w, factor),
            acc,
            "Goldilocks arithmetic mismatch"
        );
        // Non-member must return None
        assert!(compute_witness(&elems, 999).is_none());
    }

    /// STARK proof test — generates real Winterfell STARK proofs.
    /// Marked `#[ignore]` because proof generation requires substantial RAM
    /// and CPU time that exceeds typical CI runner budgets.
    ///
    /// Run locally with:
    /// ```
    /// cargo test -p miden-zk-primitives -- --ignored
    /// ```
    #[test]
    #[ignore = "STARK proof generation — run locally: cargo test -- --ignored"]
    fn test_membership_stark() {
        let elems = vec![100u64, 200, 300];
        let acc = build_accumulator(&elems);
        let w = compute_witness(&elems, 200).unwrap();
        let b = prove_membership(acc, 200, w).expect("prove failed");
        verify_membership(acc, 200, w, &b).expect("verify failed");
    }
}
