//! Shared helpers: compile + prove + verify a MASM program.
//!
//! Every higher-level module calls `prove_program` / `verify_proof`.
//! These functions wrap the **real** Miden VM API:
//! - [`miden_vm::prove`] — generates a genuine STARK proof
//! - [`miden_vm::verify`] — verifies the proof without re-executing

use miden_vm::{
    prove, verify, Assembler, DefaultHost, ExecutionProof, Kernel, MemAdviceProvider, ProgramInfo,
    ProvingOptions, StackInputs, StackOutputs,
};

/// A serialised STARK proof together with the public stack outputs.
#[derive(Debug, Clone)]
pub struct ProofBundle {
    /// Raw proof bytes — store, send, or verify later.
    pub proof_bytes: Vec<u8>,
    /// The stack outputs produced by the program.
    pub outputs: Vec<u64>,
}

/// Compile `masm_src`, run it with `inputs` pushed onto the stack, and return
/// a real STARK [`ProofBundle`].
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

    let host = DefaultHost::new(MemAdviceProvider::default());
    let (outputs, proof) = prove(&program, stack_inputs, host, ProvingOptions::default())
        .map_err(|e| format!("prove: {e}"))?;

    Ok(ProofBundle {
        proof_bytes: proof.to_bytes(),
        outputs: outputs.stack().iter().map(|f| f.as_int()).collect(),
    })
}

/// Verify a [`ProofBundle`] against `masm_src` and `inputs`.
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

    let program_info = ProgramInfo::new(program.hash(), Kernel::default());
    verify(program_info, stack_inputs, stack_outputs, proof).map_err(|e| format!("verify: {e}"))?;

    Ok(())
}
