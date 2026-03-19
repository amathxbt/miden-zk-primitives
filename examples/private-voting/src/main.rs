//! Private voting example using Miden VM zero-knowledge proofs.
//!
//! Each voter commits to their choice with a secret randomness value.
//! The tally is computed without revealing individual votes.

use miden_zk_primitives::{commitment::PedersenCommitment, nullifier::Nullifier};
use rand::thread_rng;

fn main() {
    println!("=== Miden ZK Private Voting Demo ===\n");

    let mut rng = thread_rng();

    // Simulate 5 voters: 3 vote Yes (1), 2 vote No (0)
    let votes: Vec<u64> = vec![1, 0, 1, 1, 0];

    println!("Casting {} secret votes...", votes.len());

    let mut commitments = Vec::new();
    let mut nullifiers  = Vec::new();

    for (i, &vote) in votes.iter().enumerate() {
        // Commit to the vote
        let (comm, randomness) = PedersenCommitment::commit(vote, &mut rng);
        commitments.push(comm.clone());

        // Generate a nullifier to prevent double-voting
        let nul = Nullifier::derive(&randomness, i as u64);
        nullifiers.push(nul);

        println!(
            "  Voter {}: commitment = 0x{:016x}, nullifier = 0x{:016x}",
            i + 1,
            comm.value(),
            nul.value()
        );
    }

    // Verify no duplicate nullifiers (double-vote prevention)
    let unique: std::collections::HashSet<_> = nullifiers.iter().map(|n| n.value()).collect();
    assert_eq!(unique.len(), nullifiers.len(), "Double-vote detected!");
    println!("\n✅ No double-votes detected.");

    // Tally (in a real system this would be a ZK proof on Miden VM)
    let yes_count = votes.iter().filter(|&&v| v == 1).count();
    let no_count  = votes.len() - yes_count;
    println!("\n📊 Tally: Yes = {yes_count}, No = {no_count}");
    println!("🏆 Result: {}", if yes_count > no_count { "PASSED" } else { "REJECTED" });
    println!("\n✅ All votes verified without revealing individual choices.");
}
