//! Range proof: prove `min ≤ value ≤ max` inside Miden VM.
//!
//! Uses Miden VM's native `u32` comparison instructions which are specifically
//! optimised for range checks in the STARK proof system.
//!
//! ## MASM program
//!
//! ```text
//! begin
//!   # Stack: [max, min, value]
//!   dup.0   # duplicate value
//!   movup.2 # bring min to top
//!   u32gte  # value >= min?  (1 = yes)
//!   assert  # abort if value < min
//!   u32lte  # value <= max?  (1 = yes)
//!   assert  # abort if value > max
//!   push.1  # success
//! end
//! ```
//!
//! If the value is out of range the VM aborts and **no proof is generated**,
//! making it impossible to fake a proof.

use crate::utils::{prove_program, verify_proof, ProofBundle};

/// MASM program that verifies `min ≤ value ≤ max`.
///
/// Public inputs (bottom → top of stack): `[max, min, value]`
const RANGE_MASM: &str = "
begin
    # Stack: [value, min, max]  (top = value)
    dup.0         # [value, value, min, max]
    movup.2       # [min, value, value, max]
    u32gte        # [value>=min, value, max]
    assert        # abort if value < min
    movup.1       # [value, max]
    u32lte        # [value<=max]
    assert        # abort if value > max
    push.1        # explicit success signal
end
";

/// Prove that `value` lies in `[min, max]`.
///
/// Both `min`, `max`, and `value` must be valid `u32` values (< 2^32).
///
/// # Errors
///
/// Returns an error if `value` is outside `[min, max]` (the VM aborts and
/// no proof can be generated — the prover cannot cheat).
///
/// # Example
///
/// ```rust,no_run
/// use miden_zk_primitives::range_proof::prove_range;
/// let bundle = prove_range(25, 18, 120).unwrap();
/// assert!(miden_zk_primitives::range_proof::verify_range(25, 18, 120, &bundle).is_ok());
/// ```
pub fn prove_range(value: u64, min: u64, max: u64) -> Result<ProofBundle, String> {
    if value < min || value > max {
        return Err(format!("value {value} not in [{min}, {max}]"));
    }
    // Stack (bottom → top): [max, min, value]
    prove_program(RANGE_MASM, &[max, min, value])
}

/// Verify a range proof.
///
/// # Errors
///
/// Returns an error if the STARK proof is invalid.
pub fn verify_range(value: u64, min: u64, max: u64, bundle: &ProofBundle) -> Result<(), String> {
    verify_proof(RANGE_MASM, &[max, min, value], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_range_proves_and_verifies() {
        let bundle = prove_range(25, 18, 120).expect("prove failed");
        verify_range(25, 18, 120, &bundle).expect("verify failed");
    }

    #[test]
    fn boundary_values() {
        for v in [18u64, 60, 120] {
            let b = prove_range(v, 18, 120).unwrap_or_else(|e| panic!("prove({v}): {e}"));
            verify_range(v, 18, 120, &b).unwrap_or_else(|e| panic!("verify({v}): {e}"));
        }
    }

    #[test]
    fn out_of_range_is_rejected() {
        // Pre-check prevents even calling the VM with bad values.
        assert!(prove_range(17, 18, 120).is_err());
        assert!(prove_range(121, 18, 120).is_err());
    }

    #[test]
    fn wrong_inputs_fail_verify() {
        let bundle = prove_range(25, 18, 120).unwrap();
        // Verify with wrong value → stack output mismatch
        assert!(verify_range(30, 18, 120, &bundle).is_err());
    }
}
