use crate::utils::{prove_program, verify_program, ProofBundle};

const NULLIFIER_SRC: &str = "
begin
    push.0.0.0.0.0.0.0.0.0.0
    hperm
end
";

pub fn prove_nullifier(secret_key: u64, note_index: u64) -> Result<ProofBundle, Box<dyn std::error::Error>> {
    prove_program(NULLIFIER_SRC, &[note_index, secret_key])
}

pub fn verify_nullifier(secret_key: u64, note_index: u64, bundle: &ProofBundle) -> Result<(), Box<dyn std::error::Error>> {
    verify_program(NULLIFIER_SRC, &[note_index, secret_key], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_nullifier() {
        let b = prove_nullifier(12345, 1).expect("prove failed");
        verify_nullifier(12345, 1, &b).expect("verify failed");
    }
}
