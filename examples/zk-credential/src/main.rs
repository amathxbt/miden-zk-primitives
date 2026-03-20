//! ZK credential: prove membership in an allowlist without revealing identity.

use miden_zk_primitives::set_membership::SetMembershipProof;

fn main() {
    println!("=== Miden ZK Credential Demo ===\n");

    // Allowlisted members (e.g. verified KYC IDs, hashed).
    let allowlist: Vec<u64> = vec![
        0xdead_beef_0000_0001,
        0xdead_beef_0000_0002,
        0xdead_beef_0000_0003,
        0xdead_beef_0000_0004,
    ];

    // Prover knows they are member #3 but reveals only the proof.
    let my_index = 2usize; // 0-indexed
    let stranger_index = 99usize;

    println!("Allowlist size: {}", allowlist.len());
    println!("Proving membership for a hidden identity...\n");

    match SetMembershipProof::prove(&allowlist, my_index) {
        Ok(proof) => {
            let valid = proof.verify(&allowlist);
            println!("  \u{2705} Proof generated. Valid: {valid}");
            println!("  (No individual identity was revealed)");
        }
        Err(e) => println!("  \u{274c} Proof generation failed: {e}"),
    }

    println!();
    println!("Attempting proof for non-member...");
    match SetMembershipProof::prove(&allowlist, stranger_index) {
        Ok(_) => println!("  \u{26a0}\u{fe0f}  Unexpected success"),
        Err(e) => println!("  \u{2705} Correctly rejected: {e}"),
    }
}
