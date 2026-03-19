//! ZK credential: prove membership in an allowlist without revealing your identity.

use miden_zk_primitives::set_membership::SetMembershipProof;

fn main() {
    println!("=== Miden ZK Credential Demo ===\n");

    // Allowlisted members (e.g. verified KYC IDs, hashed)
    let allowlist: Vec<u64> = vec![
        0xdeadbeef_00000001,
        0xdeadbeef_00000002,
        0xdeadbeef_00000003,
        0xdeadbeef_00000004,
    ];

    // Prover knows they are member #3 but reveals only the proof
    let my_id: u64 = 0xdeadbeef_00000003;
    let stranger_id: u64 = 0xdeadbeef_00000099;

    println!("Allowlist size: {}", allowlist.len());
    println!("Proving membership for a hidden identity...\n");

    match SetMembershipProof::prove(my_id, &allowlist) {
        Ok(proof) => {
            let valid = proof.verify(&allowlist);
            println!("  ✅ Proof generated. Valid: {valid}");
            println!("  (No individual identity was revealed)");
        }
        Err(e) => println!("  ❌ Proof generation failed: {e}"),
    }

    println!();
    println!("Attempting proof for non-member...");
    match SetMembershipProof::prove(stranger_id, &allowlist) {
        Ok(_) => println!("  ⚠️  Unexpected success"),
        Err(e) => println!("  ✅ Correctly rejected: {e}"),
    }
}
