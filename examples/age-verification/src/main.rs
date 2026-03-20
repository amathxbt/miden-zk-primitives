//! Age-verification example.
//!
//! Proves that `age >= 18` without disclosing the exact age.
//! Uses a range proof: prove the committed value lies in `[18, 120]`.

use miden_zk_primitives::range_proof::RangeProof;

fn age_gate(age: u64) -> bool {
    println!("Generating range proof for age = {age} (hidden)...");
    match RangeProof::prove(age, 18, 120) {
        Ok(proof) => {
            let ok = proof.verify(18, 120);
            println!("  Proof valid: {ok}");
            ok
        }
        Err(e) => {
            println!("  Cannot prove: {e}");
            false
        }
    }
}

fn main() {
    println!("=== Miden ZK Age Verification Demo ===\n");

    for age in [17u64, 18, 25, 119, 120, 121] {
        let allowed = age_gate(age);
        println!(
            "  Age {age}: access {}\n",
            if allowed {
                "GRANTED \u{2705}"
            } else {
                "DENIED  \u{274c}"
            }
        );
    }
}
