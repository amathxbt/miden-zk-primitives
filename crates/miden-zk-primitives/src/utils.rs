use miden_vm::{
    prove, verify, Assembler, ExecutionOptions, ExecutionProof,
    KernelLibrary, ProgramInfo, StackInputs, StackOutputs,
    utils::Serializable,
};

#[derive(Debug, Clone)]
pub struct ProofBundle {
    pub proof_bytes: Vec<u8>,
    pub stack_outputs: Vec<u64>,
    pub program_hash: [u8; 32],
}

pub fn prove_program(
    source: &str,
    inputs: &[u64],
) -> Result<ProofBundle, Box<dyn std::error::Error>> {
    let assembler = Assembler::default();
    let program = assembler.compile(source)?;
    let stack_inputs = StackInputs::try_from_ints(inputs.iter().copied())?;
    let options = ExecutionOptions::new(Some(2_u32.pow(20)), 64, false, false)?;
    let proven = prove(&program, stack_inputs, options)?;
    let outputs: Vec<u64> = proven.stack_outputs().stack().iter()
        .map(|v| v.as_int()).collect();
    let proof_bytes = proven.into_proof().to_bytes();
    let hash_bytes: [u8; 32] = program.hash().as_bytes()
        .try_into().unwrap_or([0u8; 32]);
    Ok(ProofBundle { proof_bytes, stack_outputs: outputs, program_hash: hash_bytes })
}

pub fn verify_program(
    source: &str,
    inputs: &[u64],
    bundle: &ProofBundle,
) -> Result<(), Box<dyn std::error::Error>> {
    let assembler = Assembler::default();
    let program = assembler.compile(source)?;
    let stack_inputs = StackInputs::try_from_ints(inputs.iter().copied())?;
    let stack_outputs = StackOutputs::try_from_ints(
        bundle.stack_outputs.iter().copied()
    )?;
    let program_info = ProgramInfo::new(program.hash(), KernelLibrary::default());
    let proof = ExecutionProof::from_bytes(&bundle.proof_bytes)?;
    verify(program_info, stack_inputs, stack_outputs, proof)?;
    Ok(())
}
