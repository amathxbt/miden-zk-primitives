# miden-zk-primitives

[![CI](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml/badge.svg)](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![no_std](https://img.shields.io/badge/no__std-compatible-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)

> **A production-quality library of zero-knowledge cryptographic primitives for the [Miden VM](https://github.com/0xMiden/miden-vm) ecosystem.**

Miden VM is a powerful STARK-based virtual machine for writing and proving arbitrary computations. This library fills a gap in the ecosystem by providing ready-to-use ZK primitives — commitments, Merkle trees, nullifiers, range proofs, and set-membership proofs — along with three complete example applications.

---

## ✨ Features

| Primitive | Description |
|-----------|-------------|
| **`PedersenCommitment`** | Hiding + binding commitment to `u64` values |
| **`MerkleTree`** | Binary Merkle tree — build, prove, verify |
| **`Nullifier`** | Deterministic collision-resistant tag (double-spend prevention) |
| **`RangeProof`** | Prove `value ∈ [min, max]` without revealing the value |
| **`SetMembershipProof`** | Prove element ∈ set without revealing which element |

---

## 🚀 Quick Start

```toml
# Cargo.toml
[dependencies]
miden-zk-primitives = { git = "https://github.com/amathxbt/miden-zk-primitives" }
```

```rust
use miden_zk_primitives::{
    commitment::PedersenCommitment,
    merkle::MerkleTree,
    nullifier::Nullifier,
    range_proof::RangeProof,
};
use rand::thread_rng;

// 1. Commit to a secret value
let (comm, r) = PedersenCommitment::commit(42, &mut thread_rng());
assert!(comm.open(42, r));

// 2. Merkle tree
let tree = MerkleTree::build(&[10, 20, 30, 40]);
let proof = tree.proof(1);
assert!(MerkleTree::verify(20, 1, &proof, tree.root()));

// 3. Nullifier (double-vote prevention)
let nul = Nullifier::derive(0xdeadbeef, 0);

// 4. Range proof: prove age ≥ 18 without revealing exact age
let rp = RangeProof::prove(25, 18, 120, &mut thread_rng()).unwrap();
assert!(rp.verify(18, 120));
```

---

## 🗂 Repository Structure

```
miden-zk-primitives/
├── crates/
│   └── miden-zk-primitives/    ← Core library (no_std compatible)
│       └── src/
│           ├── lib.rs
│           ├── commitment.rs
│           ├── error.rs
│           ├── merkle.rs
│           ├── nullifier.rs
│           ├── range_proof.rs
│           ├── set_membership.rs
│           └── utils.rs
└── examples/
    ├── private-voting/          ← Privacy-preserving election demo
    ├── age-verification/        ← ZK age-gate (prove ≥18 without revealing age)
    └── zk-credential/          ← Anonymous allowlist membership proof
```

---

## 🎯 Example Applications

### 🗳️ Private Voting
Each voter commits to their choice; tallying happens without revealing individual votes. Nullifiers prevent double-voting.

```bash
cargo run -p private-voting
```

### 🔞 Age Verification
Prove `age ≥ 18` using a range proof — the exact age is never disclosed.

```bash
cargo run -p age-verification
```

### 🪪 ZK Credential
Prove membership in a KYC allowlist without revealing *which* member you are.

```bash
cargo run -p zk-credential
```

---

## 🛠 Building & Testing

```bash
# Run all tests
cargo test --all-features --workspace

# Run clippy (zero warnings policy)
cargo clippy --all-features --workspace

# Check formatting
cargo fmt --all -- --check

# Build docs
cargo doc --all-features --no-deps --open
```

---

## 📐 Design Principles

1. **`no_std` first** – the core library works in constrained environments; `std`-only code is gated behind the `std` feature flag.
2. **Interface-first** – each primitive defines a clean API today; the cryptographic backend (STARK proofs via Miden) can be wired in without breaking callers.
3. **Zero warnings** – `RUSTFLAGS=-D warnings` in CI; `#![deny(missing_docs)]` enforced.
4. **Battle-tested tests** – every primitive has unit tests covering happy paths, boundary values, and tamper-detection.

---

## 🔒 Security Notice

This library is **research-grade**. The primitives have not been independently audited. Do **not** use in production systems without a thorough security review. See [SECURITY.md](SECURITY.md) for the vulnerability disclosure process.

---

## 🤝 Contributing

PRs are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

---

## 📄 License

[MIT](LICENSE) © 2025 amathxbt
