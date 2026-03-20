//! ZK credential — prove accumulator membership via real Miden STARK proof.
//!
//! The issuer builds an accumulator over approved credential hashes.
//! A credential holder proves membership without revealing their identity.

use miden_zk_primitives::accumulator::{
    build_accumulator, compute_witness, prove_membership, verify_membership,
};

fn main() {
    println!("=== Miden ZK Credential (Real STARK Proofs) ===\n");

    // Approved credentials (e.g. hashed KYC IDs)
    let credentials: Vec<u64> = vec![0xDEAD_0001, 0xDEAD_0002, 0xDEAD_0003, 0xDEAD_0004];

    let acc = build_accumulator(&credentials);
    println!("Accumulator value: {acc:#x}");
    println!("Credential count:  {}\n", credentials.len());

    // Member proves they hold credential 0xDEAD_0003
    let my_cred = 0xDEAD_0003_u64;
    let witness = compute_witness(&credentials, my_cred).expect("credential not found");

    println!("Proving membership for credential (hidden from verifier)...");
    match prove_membership(acc, my_cred, witness) {
        Ok(bundle) => {
            println!("✅ Proof generated ({} bytes)", bundle.proof_bytes.len());
            match verify_membership(acc, my_cred, witness, &bundle) {
                Ok(()) => println!("✅ Proof VERIFIED — credential accepted"),
                Err(e) => println!("❌ Verify failed: {e}"),
            }
        }
        Err(e) => println!("❌ Prove failed: {e}"),
    }

    println!("\nAttempting non-member proof...");
    let stranger = 0xDEAD_9999_u64;
    match compute_witness(&credentials, stranger) {
        None => println!("✅ Correctly rejected: stranger not in accumulator"),
        Some(_) => println!("❌ Unexpected: stranger found a witness"),
    }
}
