# miden-zk-primitives

[![CI](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml/badge.svg)](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange)](https://rustup.rs)
[![Miden VM](https://img.shields.io/badge/Miden%20VM-v0.11-blue)](https://github.com/0xMiden/miden-vm)

> **Production-quality zero-knowledge primitives built 100% on the [Miden VM](https://github.com/0xMiden/miden-vm) — a STARK-based virtual machine.**

---


Every function in this library:

1. **Compiles  Miden Assembly (MASM)** programs using `miden_vm::Assembler`
2. **Executes them through the real Miden VM processor**
3. **Generates genuine STARK proofs** via `miden_vm::prove` (Winterfell backend)
4. **Verifies proofs** with `miden_vm::verify` — no trusted setup, post-quantum secure

The **only** external dependency is `miden-vm = "0.11"`. Every primitive uses
native Miden VM instructions (`hperm`, `mtree_verify`, `u32gte`, `u32lte`,
`u32wrapping_mul`, `assert_eq`) — nothing is simulated or faked.

---




- **All CI checks pass** (Rustfmt, Clippy `-D warnings`, Tests, Docs, Build Examples)
- **Real STARK proofs** — proof bytes are serialised, can be stored/transmitted/verified
- **Clean public API** — add `miden-zk-primitives` to your `Cargo.toml` and call the functions
- **5 working example applications** demonstrating real-world use cases

```toml
# Add to your Cargo.toml
[dependencies]
miden-zk-primitives = { git = "https://github.com/amathxbt/miden-zk-primitives" }
```

---

## ✅ Can the Miden team and other teams use it?

**Yes.** The repository is public, well-documented, and CI-clean:

- **GitHub:** https://github.com/amathxbt/miden-zk-primitives
- **CI:** All 5 jobs green on every push to `main`
- **0 Clippy warnings** — `-D warnings` is enforced
- **Docs:** `cargo doc --no-deps --workspace` builds without errors

---

## Architecture

```
miden-zk-primitives/
├── crates/miden-zk-primitives/    # Core library
│   └── src/
│       ├── utils.rs               # prove_program() / verify_proof() — Miden VM wrappers
│       ├── commitment.rs          # RPO hash commitment  [hperm]
│       ├── merkle.rs              # Merkle membership    [mtree_verify]
│       ├── nullifier.rs           # Spend-once nullifier [hperm]
│       ├── range_proof.rs         # Range proof          [u32gte / u32lte]
│       ├── set_membership.rs      # Set membership       [mtree_verify]
│       ├── schnorr.rs             # Schnorr signatures   [u32wrapping_mul]
│       └── accumulator.rs        # Membership accumulator [u32wrapping_mul]
└── examples/
    ├── private-voting/            # Anonymous voting (commitment + nullifier)
    ├── age-verification/          # Prove age ≥ 18 (range proof)
    ├── zk-credential/             # KYC allowlist (accumulator membership)
    ├── schnorr-sig/               # Schnorr signature demo
    └── accumulator/               # Accumulator membership demo
```

---

## Why Miden VM?

| Feature | This library |
|---------|-------------|
| **Proof system** | STARK (transparent, no trusted setup) |
| **Hash function** | RPO — Rescue Prime Optimized (Miden's native hash) |
| **Field** | Goldilocks 64-bit (`p = 2⁶⁴ − 2³² + 1`) |
| **Security** | Post-quantum (hash-based, not elliptic curves) |
| **Proof size** | ~50–200 KB depending on program complexity |
| **Verify time** | Milliseconds — much faster than re-execution |

---

## Primitives

### `commitment` — RPO Hash Commitment

Uses Miden VM's native `hperm` (Rescue Prime Optimized permutation).

```rust
use miden_zk_primitives::commitment::{prove_commit_open, verify_commit_open};

let bundle = prove_commit_open(42, 7)?;
println!("STARK proof: {} bytes", bundle.proof_bytes.len());

verify_commit_open(42, 7, &bundle)?;
println!("✅ Commitment verified!");
```

### `range_proof` — Native u32 Range Check

Uses Miden VM's `u32gte` and `u32lte` instructions.

```rust
use miden_zk_primitives::range_proof::{prove_range, verify_range};

let bundle = prove_range(25, 18, 120)?;   // prove age ∈ [18, 120]
verify_range(25, 18, 120, &bundle)?;
println!("✅ Age is in [18, 120] — STARK proof verified");
```

### `nullifier` — Spend-Once Token

```rust
use miden_zk_primitives::nullifier::{prove_nullifier, verify_nullifier};

let bundle = prove_nullifier(secret_key, note_index)?;
println!("Nullifier: {:#x}", bundle.outputs[0]);
verify_nullifier(secret_key, note_index, &bundle)?;
```

### `schnorr` — Schnorr-like Digital Signatures

```rust
use miden_zk_primitives::schnorr::{keypair, sign, prove_schnorr_verify, verify_schnorr_verify};

let (pk, sk) = keypair(my_secret);
let (r_point, e, s) = sign(sk, pk, nonce, msg_hash);
let bundle = prove_schnorr_verify(pk, r_point, e, s)?;
verify_schnorr_verify(pk, r_point, e, s, &bundle)?;
```

### `accumulator` — Membership Accumulator

```rust
use miden_zk_primitives::accumulator::*;

let elements = vec![100u64, 200, 300];
let acc = build_accumulator(&elements);
let witness = compute_witness(&elements, 100).unwrap();
let bundle = prove_membership(acc, 100, witness)?;
verify_membership(acc, 100, witness, &bundle)?;
```

### `merkle` — Native `mtree_verify`

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

## How the Proof System Works

```
Your MASM program + Public inputs
          │
          ▼
  ┌───────────────────┐
  │   Miden Prover    │  ← miden_vm::prove()
  │   (Winterfell     │
  │    STARK backend) │
  └───────────────────┘
          │
          ▼
  ┌───────────────────┐          ┌──────────────────────┐
  │  STARK proof      │─────────▶│  miden_vm::verify()  │
  │  (~100 KB bytes)  │          │  (milliseconds,      │
  └───────────────────┘          │   no re-execution)   │
                                 └──────────────────────┘
```

- **No trusted setup** — STARK proofs are fully transparent
- **Post-quantum secure** — based on hash functions
- **Proof size** — O(log² n) in number of execution steps
- **Verification** — O(log n), far faster than re-execution

---

## Requirements

- Rust 1.80+
- ~2–4 GB RAM for proof generation (STARK provers are memory-intensive)
- No system dependencies beyond the Rust toolchain

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

Join the Miden community:
- [Discord](https://discord.gg/MtvzuHjZ)
- [GitHub Discussions](https://github.com/0xMiden/miden-vm/discussions)

---

## License

MIT — see [LICENSE](LICENSE)

---

## Acknowledgements

Built on [Miden VM](https://github.com/0xMiden/miden-vm) by the [0xMiden team](https://github.com/0xMiden).
