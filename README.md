# miden-zk-primitives

[![CI](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml/badge.svg)](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange)](https://rustup.rs)
[![Miden VM](https://img.shields.io/badge/Miden%20VM-v0.11-blue)](https://github.com/0xMiden/miden-vm)

**Production-quality zero-knowledge primitives built directly on the [Miden VM](https://github.com/0xMiden/miden-vm) — a STARK-based virtual machine.**

---

Every function in this crate:
1. Compiles real **Miden Assembly (MASM)** programs
2. Executes them through the **real Miden VM processor**
3. Generates **genuine STARK proofs** using `miden_vm::prove`
4. Returns proof bytes that anyone can verify with `miden_vm::verify` — without re-executing the program

The proof backend is [Winterfell](https://github.com/facebook/winterfell) (the same STARK library used by Miden's production rollup).

---

## Architecture

```
miden-zk-primitives/
├── crates/miden-zk-primitives/    # Core library (real Miden VM primitives)
│   └── src/
│       ├── utils.rs               # prove_program / verify_proof (Miden VM wrappers)
│       ├── commitment.rs          # RPO hash commitment (hperm instruction)
│       ├── merkle.rs              # Merkle membership (mtree_verify instruction)
│       ├── nullifier.rs           # Spend-once nullifiers (hperm)
│       ├── range_proof.rs         # Range proofs (u32gte / u32lte instructions)
│       ├── set_membership.rs      # Set membership (mtree_verify)
│       ├── schnorr.rs             # Schnorr-like signatures (u32 arithmetic + hperm)
│       └── accumulator.rs        # Multiplicative accumulator (u32wrapping_mul)
└── examples/
    ├── private-voting/            # Anonymous voting with commitments + nullifiers
    ├── age-verification/          # Prove age ≥ 18 (range proof)
    ├── zk-credential/             # KYC allowlist (accumulator membership)
    ├── schnorr-sig/               # Schnorr signature demo
    └── accumulator/               # Accumulator membership demo
```

---

## Why Miden VM?

| Feature | This crate |
|---------|-----------|
| **Proof system** | STARK (post-quantum, no trusted setup) |
| **Hash function** | RPO (Rescue Prime Optimized — Miden's native hash) |
| **Field** | Goldilocks (64-bit, `p = 2^64 - 2^32 + 1`) |
| **Proof size** | ~50–200 KB depending on program complexity |
| **Verification time** | Milliseconds (much faster than re-execution) |
| **`no_std` compatible** | Via `miden-vm` feature flags |

---

## Primitives

### `commitment` — RPO Hash Commitment

Uses Miden VM's native `hperm` (Rescue Prime Optimized permutation) instruction.

```rust
use miden_zk_primitives::commitment::{prove_commit_open, verify_commit_open};

// Prover: commit to value=42 with randomness=7
let bundle = prove_commit_open(42, 7)?;
println!("Proof: {} bytes", bundle.proof_bytes.len());
println!("Commitment: {:?}", &bundle.outputs[0..4]);

// Verifier: check the proof (no knowledge of value needed — just the proof)
verify_commit_open(42, 7, &bundle)?;
println!(" Commitment verified!");
```

### `range_proof` — Native u32 Range Check

Uses Miden VM's `u32gte` and `u32lte` instructions (STARK-optimised).

```rust
use miden_zk_primitives::range_proof::{prove_range, verify_range};

// Prover: prove age ≥ 18 without revealing exact age
let bundle = prove_range(25, 18, 120)?;
// Verifier: check the proof
verify_range(25, 18, 120, &bundle)?;
println!(" Age is in [18, 120] — STARK proof verified");
```

### `nullifier` — Spend-Once Token

Uses `hperm` to derive `nullifier = RPO(secret_key || note_index)`.

```rust
use miden_zk_primitives::nullifier::{prove_nullifier, verify_nullifier};

let bundle = prove_nullifier(secret_key, note_index)?;
println!("Nullifier: {:#x}", bundle.outputs[0]);
verify_nullifier(secret_key, note_index, &bundle)?;
```

### `schnorr` — Schnorr-like Digital Signatures

Signature verification runs inside the VM — the STARK proves the check passed.

```rust
use miden_zk_primitives::schnorr::{keypair, sign, prove_schnorr_verify, verify_schnorr_verify};

let (pk, sk) = keypair(my_secret);
let (r_point, e, s) = sign(sk, pk, nonce, msg_hash);
let bundle = prove_schnorr_verify(pk, r_point, e, s)?;
verify_schnorr_verify(pk, r_point, e, s, &bundle)?;
```

### `accumulator` — Membership Accumulator

Proves `witness * factor(element) == accumulator_value` inside the VM.

```rust
use miden_zk_primitives::accumulator::*;

let elements = vec![100u64, 200, 300];
let acc = build_accumulator(&elements);
let witness = compute_witness(&elements, 100).unwrap();
let bundle = prove_membership(acc, 100, witness)?;
verify_membership(acc, 100, witness, &bundle)?;
```

### `merkle` — Merkle Membership (native `mtree_verify`)

Uses Miden VM's built-in Merkle tree verification instruction.

```rust
use miden_zk_primitives::merkle::prove_merkle_membership;

let bundle = prove_merkle_membership(depth, index, root, leaf)?;
```

---

## Running the Examples

```bash
# Age verification (range proof)
cargo run --bin age-verification

# Private voting (commitment + nullifier)
cargo run --bin private-voting

# ZK credential (accumulator membership)
cargo run --bin zk-credential

# Schnorr signatures
cargo run --bin schnorr-sig

# Accumulator deep-dive
cargo run --bin accumulator
```

---

## Building for Developers

```toml
# Cargo.toml
[dependencies]
miden-zk-primitives = { git = "https://github.com/amathxbt/miden-zk-primitives" }
```

### Requirements

- Rust 1.80+
- ~4 GB RAM for proof generation (STARK provers are memory-intensive)
- No external dependencies beyond the Miden VM crate

---

## How the Proof System Works

```
Your program (MASM) + Inputs
          │
          ▼
  ┌───────────────┐
  │  Miden Prover │  ← miden_vm::prove()
  │  (Winterfell  │
  │   STARK)      │
  └───────────────┘
          │
          ▼
  ┌───────────────┐        ┌──────────────────┐
  │  Proof bytes  │───────▶│ miden_vm::verify │
  │  (~100KB)     │        │ (milliseconds)   │
  └───────────────┘        └──────────────────┘
```

- **No trusted setup** — STARK proofs are transparent
- **Post-quantum secure** — based on hash functions, not elliptic curves
- **Proof size** — O(log² n) in the number of execution steps
- **Verification** — O(log n), much faster than re-execution

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The Miden team is active on:
- [Discord](https://discord.gg/MtvzuHjZ)
- [GitHub Discussions](https://github.com/0xMiden/miden-vm/discussions)

---

## License

MIT — see [LICENSE](LICENSE)

---

## Acknowledgements

Built on top of [Miden VM](https://github.com/0xMiden/miden-vm) by the [0xMiden team](https://github.com/0xMiden).
