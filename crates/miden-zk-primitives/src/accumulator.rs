use crate::utils::{prove_program, verify_program, ProofBundle};

fn acc_src(witness: u64, factor: u64, accumulator: u64) -> String {
    format!("begin\n    push.{witness}\n    push.{factor}\n    u32wrapping_mul\n    push.{accumulator}\n    assert_eq\nend")
}

pub fn build_accumulator(elements: &[u64]) -> u64 {
    elements.iter().fold(1u64, |acc, &e| acc.wrapping_mul(e.wrapping_add(31337)))
}

pub fn compute_witness(elements: &[u64], target: u64) -> Option<u64> {
    if !elements.contains(&target) { return None; }
    Some(elements.iter().filter(|&&e| e != target).fold(1u64, |acc, &e| acc.wrapping_mul(e.wrapping_add(31337))))
}

pub fn prove_membership(accumulator: u64, element: u64, witness: u64) -> Result<ProofBundle, String> {
    prove_program(&acc_src(witness, element.wrapping_add(31337), accumulator), &[])
}

pub fn verify_membership(accumulator: u64, element: u64, witness: u64, bundle: &ProofBundle) -> Result<(), String> {
    verify_program(&acc_src(witness, element.wrapping_add(31337), accumulator), &[], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_membership() {
        let elems = vec![100u64, 200, 300];
        let acc = build_accumulator(&elems);
        let w = compute_witness(&elems, 200).unwrap();
        let b = prove_membership(acc, 200, w).expect("prove failed");
        verify_membership(acc, 200, w, &b).expect("verify failed");
    }
}
