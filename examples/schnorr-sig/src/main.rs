//! Schnorr signature demo — sign and verify inside Miden VM.

use miden_zk_primitives::schnorr::{
    keypair, prove_schnorr_verify, sign, verify_schnorr_verify,
};

fn main() {
    println!("=== Miden ZK Schnorr Signatures (Real STARK Proofs) ===\n");

    let (pk, sk) = keypair(0xDEAD_BEEF);
    println!("Public key: {pk:#010x}");

    let message = b"Miden is real ZK";
    let msg_hash = message.iter().enumerate().fold(0u64, |acc, (i, &b)| {
        acc.wrapping_add((b as u64).wrapping_mul((i as u64 + 1).wrapping_mul(0x9e37_79b9)))
    }) % (1u64 << 32);

    let r_nonce = 0xC0FFEE_u64;
    let (r_point, e, s) = sign(sk, pk, r_nonce, msg_hash);
    println!("Signature: R={r_point:#010x}  e={e:#010x}  s={s:#010x}");

    print!("\nProving signature validity inside Miden VM... ");
    match prove_schnorr_verify(pk, r_point, e, s) {
        Ok(bundle) => {
            println!("✅ proof={} bytes", bundle.proof_bytes.len());
            verify_schnorr_verify(pk, r_point, e, s, &bundle).expect("verify failed");
            println!("✅ Signature VERIFIED by STARK proof");
        }
        Err(err) => println!("❌ {err}"),
    }

    // Show that a tampered signature produces no valid proof
    println!("\nTesting tampered signature (s+1)...");
    match prove_schnorr_verify(pk, r_point, e, s + 1) {
        Ok(_) => println!("⚠️  Unexpected success"),
        Err(_) => println!("✅ Correctly rejected by Miden VM"),
    }
}
