use crate::utils::{prove_program, verify_program, ProofBundle};

const COMMITMENT_SRC: &str = "
begin
    push.0.0.0.0.0.0.0.0.0.0
    hperm
end
";

pub fn prove_commit_open(value: u64, randomness: u64) -> Result<ProofBundle, String> {
    prove_program(COMMITMENT_SRC, &[randomness, value])
}

pub fn verify_commit_open(value: u64, randomness: u64, bundle: &ProofBundle) -> Result<(), String> {
    verify_program(COMMITMENT_SRC, &[randomness, value], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_commit_open() {
        let b = prove_commit_open(42, 7).expect("prove failed");
        verify_commit_open(42, 7, &b).expect("verify failed");
    }
}
