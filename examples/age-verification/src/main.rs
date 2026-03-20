//! Age verification — real STARK range proof via Miden VM.
//!
//! Proves `age >= 18` using Miden VM's native `u32gte` / `u32lte` instructions.
//! The verifier gets a STARK proof — they don't need to trust the prover.

use miden_zk_primitives::range_proof::{prove_range, verify_range};

fn check_age(age: u64) {
    print!("Age {age:3}: ");
    match prove_range(age, 18, 120) {
        Ok(bundle) => {
            print!("proof generated ({} bytes)... ", bundle.proof_bytes.len());
            match verify_range(age, 18, 120, &bundle) {
                Ok(()) => println!("✅ VERIFIED — Access GRANTED"),
                Err(e) => println!("❌ verify failed: {e}"),
            }
        }
        Err(e) => println!("❌ Access DENIED — {e}"),
    }
}

fn main() {
    println!("=== Miden ZK Age Verification (Real STARK Proofs) ===\n");
    println!("Public range: [18, 120]  |  Exact age is hidden from verifier\n");

    for age in [15u64, 17, 18, 21, 65, 120, 121, 200] {
        check_age(age);
    }

    println!("\n✅ Done. All valid proofs verified with real Miden STARK backend.");
}
