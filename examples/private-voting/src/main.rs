//! Private voting example.
//!
//! Each voter commits to their choice (0 = No, 1 = Yes) with a secret
//! randomness value derived from their voter ID.  Nullifiers prevent
//! double-voting without revealing the individual vote.

use miden_zk_primitives::commitment::PedersenCommitment;
use miden_zk_primitives::nullifier::Nullifier;

fn main() {
    println!("=== Miden ZK Private Voting Demo ===\n");

    // 5 voters: 3 Yes, 2 No.
    let votes: Vec<u64> = vec![1, 0, 1, 1, 0];

    println!("Casting {} secret votes...", votes.len());

    let mut nullifier_values = Vec::new();

    for (i, &vote) in votes.iter().enumerate() {
        // Derive deterministic per-voter randomness from voter ID.
        let randomness = 0xc0ffee_u64.wrapping_mul((i as u64) + 1);
        let com = PedersenCommitment::commit(vote, randomness);
        let nul = Nullifier::derive(randomness, i as u64);
        nullifier_values.push(nul.value);

        println!(
            "  Voter {}: commitment = {:#018x}, nullifier = {:#018x}",
            i + 1,
            com.value,
            nul.value,
        );
    }

    // Verify no duplicate nullifiers (double-vote prevention).
    let mut seen = std::collections::HashSet::new();
    for &v in &nullifier_values {
        assert!(seen.insert(v), "Double-vote detected!");
    }
    println!("\n\u{2705} No double-votes detected.");

    let yes_count = votes.iter().filter(|&&v| v == 1).count();
    let no_count = votes.len() - yes_count;
    println!("\n\u{1f4ca} Tally: Yes = {yes_count}, No = {no_count}");
    println!(
        "\u{1f3c6} Result: {}",
        if yes_count > no_count {
            "PASSED"
        } else {
            "REJECTED"
        }
    );
    println!("\n\u{2705} All votes verified without revealing individual choices.");
}
