use crate::utils::{prove_program, verify_program, ProofBundle};

fn range_src(value: u64, lo: u64, hi: u64) -> String {
    format!("begin\n    push.{value}\n    push.{lo}\n    u32gte\n    assert\n    push.{value}\n    push.{hi}\n    u32lte\n    assert\nend")
}

pub fn prove_range(value: u64, lo: u64, hi: u64) -> Result<ProofBundle, String> {
    prove_program(&range_src(value, lo, hi), &[])
}

pub fn verify_range(value: u64, lo: u64, hi: u64, bundle: &ProofBundle) -> Result<(), String> {
    verify_program(&range_src(value, lo, hi), &[], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_range_pass() {
        let b = prove_range(25, 18, 120).expect("prove failed");
        verify_range(25, 18, 120, &b).expect("verify failed");
    }
}
