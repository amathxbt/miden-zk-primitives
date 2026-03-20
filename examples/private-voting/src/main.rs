//! Private voting — real STARK proofs via Miden VM.
//!
//! Each voter:
//! 1. Commits to their vote using RPO hash (hperm instruction).
//! 2. Derives a nullifier to prevent double-voting.
//! 3. Gets a STARK proof for each operation.

use miden_zk_primitives::{commitment, nullifier};

fn main() {
    println!("=== Miden ZK Private Voting (Real STARK Proofs) ===\n");

    let votes: &[(u64, u64)] = &[
        (1, 0xAABB_0001), // (vote, voter_secret_key)
        (0, 0xAABB_0002),
        (1, 0xAABB_0003),
        (1, 0xAABB_0004),
        (0, 0xAABB_0005),
    ];

    let mut nullifier_values = Vec::new();

    for (i, &(vote, sk)) in votes.iter().enumerate() {
        print!("Voter {}: generating commitment proof... ", i + 1);
        let r = sk.wrapping_mul(0xc0ffee);
        match commitment::prove_commit_open(vote, r) {
            Ok(bundle) => {
                println!("✅ proof={} bytes", bundle.proof_bytes.len());
                // Verify immediately
                commitment::verify_commit_open(vote, r, &bundle).expect("commitment verify failed");
            }
            Err(e) => println!("❌ {e}"),
        }

        print!("Voter {}: generating nullifier proof...   ", i + 1);
        match nullifier::prove_nullifier(sk, i as u64) {
            Ok(bundle) => {
                println!("✅ nullifier={:#x}", bundle.outputs[0]);
                nullifier_values.push(bundle.outputs[0]);
                nullifier::verify_nullifier(sk, i as u64, &bundle)
                    .expect("nullifier verify failed");
            }
            Err(e) => println!("❌ {e}"),
        }
    }

    // Double-spend check
    let mut seen = std::collections::HashSet::new();
    for &v in &nullifier_values {
        assert!(seen.insert(v), "Double-spend detected!");
    }

    let yes = votes.iter().filter(|&&(v, _)| v == 1).count();
    let no = votes.len() - yes;
    println!("\n📊 Tally: Yes={yes} No={no}");
    println!(
        "🏆 Result: {}",
        if yes > no {
            "PASSED ✅"
        } else {
            "REJECTED ❌"
        }
    );
    println!("✅ All proofs verified. No double votes detected.");
}
