//! Core prove/verify helpers wrapping the real Miden VM (0.11.x).
//!
//! Every primitive in this crate compiles a MASM source string into a
//! [`Program`], runs it on the Miden VM to obtain a STARK proof, and
//! then verifies the proof using the same VM.

use miden_vm::{
    Assembler, DefaultHost, ExecutionProof, ProgramInfo, ProvingOptions, StackInputs,
    StackOutputs,
};

/// A bundle that carries everything a verifier needs: the raw STARK
/// proof bytes, the public stack outputs, and the program hash.
#[derive(Debug, Clone)]
pub struct ProofBundle {
    /// STARK proof serialised to bytes.
    pub proof_bytes: Vec<u8>,
    /// Top-of-stack values (up to 16 field elements, as `u64`).
    pub outputs: Vec<u64>,
    /// 32-byte program hash (MAST root).
    pub program_hash: [u8; 32],
}

/// Compile `source` (MASM), execute it with `inputs` on the stack,
/// and return a [`ProofBundle`] on success.
pub fn prove_program(source: &str, inputs: &[u64]) -> Result<ProofBundle, String> {
    // 1. Compile MASM
    let program = Assembler::default()
        .assemble_program(source)
        .map_err(|e| format!("assemble error: {e}"))?;

    // 2. Build stack inputs
    let stack_inputs = StackInputs::try_from_ints(inputs.iter().copied())
        .map_err(|e| format!("stack inputs error: {e}"))?;

    // 3. Prove
    let host = DefaultHost::default();
    let (stack_outputs, proof) =
        miden_vm::prove(&program, stack_inputs, host, ProvingOptions::default())
            .map_err(|e| format!("prove error: {e}"))?;

    // 4. Collect outputs
    let outputs: Vec<u64> = stack_outputs
        .stack_truncated(16)
        .iter()
        .map(|v| v.as_int())
        .collect();

    // 5. Serialise proof
    let proof_bytes = proof.to_bytes();

    // 6. Capture program hash as [u8; 32] using the From impl on RpoDigest
    let program_hash: [u8; 32] = program.hash().into();

    Ok(ProofBundle {
        proof_bytes,
        outputs,
        program_hash,
    })
}

/// Re-assemble `source`, reconstruct inputs/outputs, deserialise the proof
/// from `bundle`, and call the Miden verifier.
pub fn verify_program(
    source: &str,
    inputs: &[u64],
    bundle: &ProofBundle,
) -> Result<(), String> {
    // 1. Compile MASM (needed for ProgramInfo)
    let program = Assembler::default()
        .assemble_program(source)
        .map_err(|e| format!("assemble error: {e}"))?;

    // 2. Build public inputs
    let stack_inputs = StackInputs::try_from_ints(inputs.iter().copied())
        .map_err(|e| format!("stack inputs error: {e}"))?;

    // 3. Build public outputs
    let stack_outputs = StackOutputs::try_from_ints(bundle.outputs.iter().copied())
        .map_err(|e| format!("stack outputs error: {e}"))?;

    // 4. Build ProgramInfo from the program (captures hash + kernel)
    let program_info = ProgramInfo::from(program);

    // 5. Deserialise proof
    let proof = ExecutionProof::from_bytes(&bundle.proof_bytes)
        .map_err(|e| format!("proof deserialisation error: {e}"))?;

    // 6. Verify
    miden_vm::verify(program_info, stack_inputs, stack_outputs, proof)
        .map_err(|e| format!("verification error: {e}"))?;

    Ok(())
}
