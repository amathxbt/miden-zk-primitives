//! Cryptographic accumulator inside Miden VM.
//!
//! Proves that an element is a member of a committed accumulator value.
//! The accumulator is a running product of element factors computed with
//! Miden VM's `u32wrapping_mul`.

use crate::utils::{prove_program, verify_proof, ProofBundle};

/// MASM: verify `witness * factor(element) == accumulator_value`.
///
/// Public inputs (bottom → top): `[acc_value, element, witness]`
///
/// Stack trace (top first):
/// ```text
/// [witness, element, acc_value]
/// swap                  → [element, witness, acc_value]
/// dup                   → [element, element, witness, acc_value]
/// movdn.2               → [element, witness, element, acc_value]
/// push.C / mul / …      → [factor, witness, element, acc_value]
/// swap                  → [witness, factor, element, acc_value]
/// mul                   → [witness*factor, element, acc_value]
/// movup.2               → [acc_value, witness*factor, element]
/// assert_eq             → [element]
/// drop / push.1         → [1]
/// ```
const ACC_VERIFY_MASM: &str = "
begin
    # Stack: [witness, element, acc_value]  (top = witness)
    # --- duplicate element (index 1) without dup.1 ---
    swap                   # [element, witness, acc_value]
    dup                    # [element, element, witness, acc_value]
    movdn.2                # [element, witness, element, acc_value]
    # --- compute factor = (element * PRIME) | 1 ---
    push.1977382967        # prime-like constant (fits u32)
    u32wrapping_mul        # [element*C, witness, element, acc_value]
    push.1
    u32or                  # force odd: [factor, witness, element, acc_value]
    # --- compute witness * factor ---
    swap                   # [witness, factor, element, acc_value]
    u32wrapping_mul        # [witness*factor, element, acc_value]
    # --- assert witness*factor == acc_value ---
    movup.2                # [acc_value, witness*factor, element]
    assert_eq              # witness*factor == acc_value?  pops both → [element]
    drop                   # drop element
    push.1
end
";

/// Prove that `witness * factor(element) == acc_value`.
///
/// # Errors
///
/// Returns an error if the equation fails inside the VM.
pub fn prove_membership(acc_value: u64, element: u64, witness: u64) -> Result<ProofBundle, String> {
    prove_program(ACC_VERIFY_MASM, &[acc_value, element, witness])
}

/// Verify an accumulator membership proof.
pub fn verify_membership(
    acc_value: u64,
    element: u64,
    witness: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    verify_proof(ACC_VERIFY_MASM, &[acc_value, element, witness], bundle)
}

/// Compute the factor for an element.
pub fn element_factor(element: u64) -> u64 {
    ((element as u128 * 1_977_382_967u128) as u64 % (1u64 << 32)) | 1
}

/// Compute an accumulator value from a list of elements.
pub fn build_accumulator(elements: &[u64]) -> u64 {
    elements.iter().fold(1u64, |acc, &e| {
        (acc as u128 * element_factor(e) as u128) as u64 % (1u64 << 32)
    })
}

/// Compute the witness for `element` (product of all other factors).
pub fn compute_witness(elements: &[u64], element: u64) -> Option<u64> {
    if !elements.contains(&element) {
        return None;
    }
    let w = elements
        .iter()
        .filter(|&&e| e != element)
        .fold(1u64, |acc, &e| {
            (acc as u128 * element_factor(e) as u128) as u64 % (1u64 << 32)
        });
    Some(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulator_prove_and_verify() {
        let elements = vec![10u64, 20, 30];
        let acc = build_accumulator(&elements);
        let witness = compute_witness(&elements, 10).unwrap();
        let bundle = prove_membership(acc, 10, witness).expect("prove failed");
        verify_membership(acc, 10, witness, &bundle).expect("verify failed");
    }

    #[test]
    fn non_member_witness_fails() {
        let elements = vec![1u64, 2, 3];
        assert!(compute_witness(&elements, 99).is_none());
    }

    #[test]
    fn tampered_witness_fails_prove() {
        let elements = vec![5u64, 6, 7];
        let acc = build_accumulator(&elements);
        let witness = compute_witness(&elements, 5).unwrap();
        // Wrong witness → VM assert_eq fails → no proof generated
        assert!(prove_membership(acc, 5, witness + 1).is_err());
    }
}
