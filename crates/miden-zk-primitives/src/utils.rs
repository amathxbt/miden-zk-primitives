use miden_vm::{
    Assembler, DefaultHost, ExecutionProof, Kernel, ProgramInfo, ProvingOptions, StackInputs,
    StackOutputs,
};

/// A self-contained bundle returned by every `prove_*` function.
///
/// - `proof_bytes`  — serialised STARK proof (can be sent to a remote verifier)
/// - `outputs`      — the top-16 stack values after execution (public outputs)
/// - `program_hash` — the RPO hash of the assembled program (uniquely identifies
///                    *what* was proved)
#[derive(Debug, Clone)]
pub struct ProofBundle {
    pub proof_bytes: Vec<u8>,
    pub outputs: Vec<u64>,
    pub program_hash: [u8; 32],
}

/// Assemble `source`, execute it on the Miden VM with `inputs` on the stack,
/// and return a STARK proof together with the public outputs.
///
/// # Errors
/// Returns a human-readable string on any assembly, execution, or proving error.
pub fn prove_program(source: &str, inputs: &[u64]) -> Result<ProofBundle, String> {
    // ── 1. Assemble the MASM source ──────────────────────────────────────────
    let program = Assembler::default()
        .assemble_program(source)
        .map_err(|e| format!("assembly error: {e}"))?;

    // ── 2. Build stack inputs ────────────────────────────────────────────────
    let stack_inputs = StackInputs::try_from_ints(inputs.iter().copied())
        .map_err(|e| format!("invalid stack inputs: {e}"))?;

    // ── 3. Prove execution ───────────────────────────────────────────────────
    let host = DefaultHost::default();
    let proving_options = ProvingOptions::default();
    let (stack_outputs, proof) =
        miden_vm::prove(&program, stack_inputs, host, proving_options)
            .map_err(|e| format!("prove error: {e}"))?;

    // ── 4. Collect public outputs (top 16 stack elements) ────────────────────
    let outputs: Vec<u64> = stack_outputs
        .stack_truncated(16)
        .iter()
        .map(|v| v.as_int())
        .collect();

    // ── 5. Capture the program hash (identifies what was proved) ─────────────
    let program_hash: [u8; 32] = program.hash().as_bytes();

    Ok(ProofBundle {
        proof_bytes: proof.to_bytes(),
        outputs,
        program_hash,
    })
}

/// Re-assemble `source`, reconstruct the public inputs/outputs from `bundle`,
/// and call the Miden verifier to check the STARK proof.
///
/// # Errors
/// Returns a human-readable string on any assembly, deserialisation, or
/// verification error.
pub fn verify_program(
    source: &str,
    inputs: &[u64],
    bundle: &ProofBundle,
) -> Result<(), String> {
    // ── 1. Re-assemble to obtain the program hash ────────────────────────────
    let program = Assembler::default()
        .assemble_program(source)
        .map_err(|e| format!("assembly error: {e}"))?;

    // ── 2. Reconstruct public inputs & outputs ───────────────────────────────
    let stack_inputs = StackInputs::try_from_ints(inputs.iter().copied())
        .map_err(|e| format!("invalid stack inputs: {e}"))?;
    let stack_outputs = StackOutputs::try_from_ints(bundle.outputs.iter().copied())
        .map_err(|e| format!("invalid stack outputs: {e}"))?;

    // ── 3. Build ProgramInfo (hash + empty kernel) ───────────────────────────
    let program_info = ProgramInfo::new(program.hash(), Kernel::default());

    // ── 4. Deserialise proof ─────────────────────────────────────────────────
    let proof = ExecutionProof::from_bytes(&bundle.proof_bytes)
        .map_err(|e| format!("proof deserialisation error: {e}"))?;

    // ── 5. Verify — the Ok value is the security level (u32); we discard it ──
    miden_vm::verify(program_info, stack_inputs, stack_outputs, proof)
        .map_err(|e| format!("verification error: {e}"))?;

    Ok(())
}
