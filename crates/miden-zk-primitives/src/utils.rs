//! Shared helpers: compile + prove + verify a MASM program via Miden VM.
//!
//! Every primitive in this crate calls these two functions, which wrap the
//! **real** Miden VM 0.11 API:
//!
//! - [`miden_vm::prove`] — generates a genuine STARK proof (Winterfell backend)
//! - [`miden_vm::verify`] — verifies the proof without re-executing the program
//!
//! Nothing here is simulated or mocked.

use miden_vm::{
    prove, verify, Assembler, DefaultHost, ExecutionProof, Kernel, ProgramInfo, ProvingOptions,
    StackInputs, StackOutputs,
};

/// A serialised STARK proof together with the public stack outputs.
///
/// Store `proof_bytes` anywhere you like; pass it (and the same `inputs`) to
/// [`verify_proof`] to confirm the computation was executed honestly.
#[derive(Debug, Clone)]
pub struct ProofBundle {
    /// Raw STARK proof bytes — store, transmit, or verify later.
    pub proof_bytes: Vec<u8>,
    /// The top-16 stack outputs produced by the program (as `u64`).
    pub outputs: Vec<u64>,
}

/// Compile `masm_src` via the Miden assembler, run it with `inputs` on the
/// stack, and return a real STARK [`ProofBundle`].
///
/// # Errors
///
/// Returns a `String` describing the first failure (compile / execute / prove).
pub fn prove_program(masm_src: &str, inputs: &[u64]) -> Result<ProofBundle, String> {
    let assembler = Assembler::default();
    let program = assembler
        .assemble_program(masm_src)
        .map_err(|e| format!("assemble: {e}"))?;

    let stack_inputs = StackInputs::try_from_ints(inputs.iter().copied())
        .map_err(|e| format!("stack inputs: {e}"))?;

    let host = DefaultHost::default();
    let (outputs, proof) = prove(&program, stack_inputs, host, ProvingOptions::default())
        .map_err(|e| format!("prove: {e}"))?;

    // Convert Felt elements to u64 (top 16 stack slots)
    let out_vec: Vec<u64> = outputs
        .stack_truncated(16)
        .iter()
        .map(|f| f.as_int())
        .collect();

    Ok(ProofBundle {
        proof_bytes: proof.to_bytes(),
        outputs: out_vec,
    })
}

/// Verify a [`ProofBundle`] against `masm_src` and `inputs`.
///
/// Re-compiles the program to get its hash, then calls [`miden_vm::verify`]
/// with the serialised proof — no re-execution required.
///
/// # Errors
///
/// Returns a `String` if the proof is invalid or cannot be deserialised.
pub fn verify_proof(masm_src: &str, inputs: &[u64], bundle: &ProofBundle) -> Result<(), String> {
    let assembler = Assembler::default();
    let program = assembler
        .assemble_program(masm_src)
        .map_err(|e| format!("assemble: {e}"))?;

    let stack_inputs = StackInputs::try_from_ints(inputs.iter().copied())
        .map_err(|e| format!("stack inputs: {e}"))?;

    let stack_outputs = StackOutputs::try_from_ints(bundle.outputs.iter().copied())
        .map_err(|e| format!("stack outputs: {e}"))?;

    let proof = ExecutionProof::from_bytes(&bundle.proof_bytes)
        .map_err(|e| format!("deserialise proof: {e}"))?;

    // miden-vm 0.11: verify(ProgramInfo, StackInputs, StackOutputs, ExecutionProof)
    // Kernel::new(&[]) creates an empty kernel (no procedure hashes).
    let kernel =
        Kernel::new(&[]).map_err(|e| format!("kernel: {e}"))?;
    let program_info = ProgramInfo::new(program.hash(), kernel);
    verify(program_info, stack_inputs, stack_outputs, proof).map_err(|e| format!("verify: {e}"))?;

    Ok(())
}
