//! Accumulator deep-dive example.

use miden_zk_primitives::accumulator::{
    build_accumulator, compute_witness, element_factor, prove_membership, verify_membership,
};

fn main() {
    println!("=== Miden ZK Accumulator (Real STARK Proofs) ===\n");

    let elements: Vec<u64> = vec![100, 200, 300, 400, 500];
    let acc = build_accumulator(&elements);

    println!("Elements: {elements:?}");
    println!("Accumulator: {acc:#x}\n");

    for &el in &elements {
        let f = element_factor(el);
        let w = compute_witness(&elements, el).unwrap();
        print!("Element {el:3}: factor={f:#010x}  witness={w:#010x}  → prove... ");
        match prove_membership(acc, el, w) {
            Ok(bundle) => {
                verify_membership(acc, el, w, &bundle).expect("verify failed");
                println!("✅ STARK proof OK ({} bytes)", bundle.proof_bytes.len());
            }
            Err(e) => println!("❌ {e}"),
        }
    }

    println!("\nNon-member test (element=999)...");
    match compute_witness(&elements, 999) {
        None => println!("✅ Correctly has no witness"),
        Some(_) => println!("❌ Unexpected witness"),
    }
}
