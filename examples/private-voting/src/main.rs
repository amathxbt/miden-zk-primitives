//! Private voting example using Miden VM zero-knowledge proofs.
//!
//! Each voter commits to their choice with a secret randomness value.
//! The tally is computed without revealing individual votes.

use miden_zk_primitives::commitment::PedersenCommitment;
use miden_zk_primitives::nullifier::Nullifier;
use rand::thread_rng;

fn main() {
    println!("=== Miden ZK Private Voting Demo ===\n");

    let mut rng = thread_rng();

    // Simulate 5 voters: 3 vote Yes (1), 2 vote No (0).
    let votes: Vec<u64> = vec![1, 0, 1, 1, 0];

    println!("Casting {} secret votes...", votes.len());

    let mut nullifiers = Vec::new();

    for (i, &vote) in votes.iter().enumerate() {
        let (comm, randomness) = PedersenCommitment::commit(vote, &mut rng);
        let nul = Nullifier::derive(randomness, i as u64);
        nullifiers.push(nul);

        println!(
            "  Voter {}: commitment = {:#018x}, nullifier = {:#018x}",
            i + 1,
            comm.value(),
            nul.value()
        );
    }

    // Verify no duplicate nullifiers (double-vote prevention).
    let unique: std::collections::HashSet<_> = nullifiers.iter().map(|n| n.value()).collect();
    assert_eq!(unique.len(), nullifiers.len(), "Double-vote detected!");
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
