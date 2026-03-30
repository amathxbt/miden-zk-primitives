# miden-zk-primitives

[![CI](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml/badge.svg)](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange)](https://rustup.rs)
[![Miden VM](https://img.shields.io/badge/Miden%20VM-v0.11.0-blue)](https://github.com/0xMiden/miden-vm)

> **Production-quality zero-knowledge primitives built 100% on the
> [Miden VM](https://github.com/0xMiden/miden-vm) — a STARK-based virtual machine.**

---

Every function in this library:

1. **Compiles Miden Assembly (MASM)** programs using `miden_vm::Assembler`
2. **Executes them through the real Miden VM processor**
3. **Generates genuine STARK proofs** via `miden_vm::prove` (Winterfell backend)
4. **Verifies proofs** with `miden_vm::verify` — no trusted setup, post-quantum secure

The **only** external dependency is `miden-vm = "=0.11.0"`. Every primitive uses
native Miden VM instructions (`hperm`, `mtree_verify`, `u32gte`, `u32lte`,
`mul`, `assert_eq`) — nothing is simulated or faked.

---

## CI / Quality

- **Fast CI passes on every push** — type-check, Clippy, fmt, compile tests, and
  lightweight unit tests all run in < 15 min on a standard GitHub runner.
- **STARK proof tests are `#[ignore]`** — they are too RAM/CPU heavy for CI
  runners but run fine locally (see below).
- **0 Clippy warnings** — `-D warnings` is enforced.
- **`miden-vm = "=0.11.0"` pinned** — the exact release is locked so the API
  never drifts between CI runs.

```toml
# Add to your Cargo.toml
[dependencies]
miden-zk-primitives = { git = "https://github.com/amathxbt/miden-zk-primitives" }
```

---

## Architecture

```
miden-zk-primitives/
├── crates/miden-zk-primitives/    # Core library
│   └── src/
│       ├── utils.rs               # prove_program() / verify_program() — Miden VM wrappers
│       ├── commitment.rs          # RPO hash commitment  [hperm]
│       ├── merkle.rs              # Merkle membership    [mtree_verify]
│       ├── nullifier.rs           # Spend-once nullifier [hperm]
│       ├── range_proof.rs         # Range proof          [u32gte / u32lte]
│       ├── set_membership.rs      # Set membership (accumulator re-export)
│       ├── schnorr.rs             # Schnorr signatures   [hperm]
│       └── accumulator.rs        # Membership accumulator [mul — Goldilocks field]
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

### `accumulator` — Membership Accumulator (Goldilocks field)

All arithmetic is performed in the Goldilocks prime field
`p = 2⁶⁴ − 2³² + 1`, which matches the Miden `mul` instruction exactly.
This avoids the u32 overflow that affected earlier versions.

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

// Requires a custom Host with a MerkleStore pre-loaded for production use.
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

## Running the STARK Proof Tests

All STARK-proof-generating tests are marked `#[ignore]` in the library so that
`cargo test` completes quickly on any machine.  To run the full suite locally:

```bash
# Run all tests including the STARK proof tests
cargo test -p miden-zk-primitives -- --ignored

# Or run the full workspace test suite
cargo test --workspace -- --include-ignored
```

> **RAM note** — Simple programs (a few instructions) typically use < 1 GB.
> Complex circuits can use more.  The examples above all complete comfortably
> on a laptop with 8 GB of RAM.

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

## CI Design

The CI is split into two jobs:

| Job | When | What it does |
|-----|------|-------------|
| **Check & Lint** | Every push / PR | `fmt`, `clippy`, `check`, `test --no-run`, `build --bins`, fast unit tests |
| **Full STARK Proof Tests** | Manual dispatch only | `test -- --include-ignored` (runs full proofs) |

This keeps every PR green within 15 minutes while still providing a way to
validate the full proof suite on demand.

---

## Requirements

- Rust **1.80+**
- Standard GitHub Actions runner (7 GB RAM) is enough for the fast CI job.
- For running STARK proof tests locally, ~4 GB RAM is sufficient for the
  simple programs in this library.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT — see [LICENSE](LICENSE)

---

## Acknowledgements

Built on [Miden VM](https://github.com/0xMiden/miden-vm)
