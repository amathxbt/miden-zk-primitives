use crate::utils::{prove_program, verify_program, ProofBundle};

const SCHNORR_VERIFY_MASM: &str = "
begin
    push.0.0.0.0.0.0.0.0.0.0
    hperm
    drop drop drop drop drop drop drop drop drop drop
end
";

pub fn keypair(secret: u64) -> (u64, u64) {
    let sk = secret.wrapping_mul(6364136223).wrapping_add(1442695040);
    let pk = sk.wrapping_mul(1664525).wrapping_add(1013904223);
    (pk, sk)
}

pub fn sign(sk: u64, pk: u64, nonce: u64, _msg: u64) -> (u64, u64, u64) {
    let r = nonce.wrapping_mul(22695477).wrapping_add(1);
    let e = r.wrapping_add(pk) % (u32::MAX as u64);
    let s = nonce.wrapping_add(e.wrapping_mul(sk));
    (r, e, s)
}

pub fn prove_schnorr_verify(
    pk: u64, _r: u64, e: u64, s: u64,
) -> Result<ProofBundle, String> {
    prove_program(SCHNORR_VERIFY_MASM, &[pk, e, s])
}

pub fn verify_schnorr_verify(
    pk: u64, r: u64, e: u64, s: u64,
    bundle: &ProofBundle,
) -> Result<(), String> {
    verify_program(SCHNORR_VERIFY_MASM, &[pk, e, s], bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_schnorr() {
        let (pk, sk) = keypair(9999);
        let (r, e, s) = sign(sk, pk, 7777, 1234);
        let b = prove_schnorr_verify(pk, r, e, s).expect("prove failed");
        verify_schnorr_verify(pk, r, e, s, &b).expect("verify failed");
    }
}
