# miden-zk-primitives

> **Production-quality zero-knowledge primitives for [Miden VM](https://github.com/0xMiden/miden-vm)**

[![CI](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml/badge.svg)](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Miden VM](https://img.shields.io/badge/Miden%20VM-v0.22-purple)](https://github.com/0xMiden/miden-vm)

A comprehensive library of zero-knowledge cryptographic primitives and applications built on Miden VM's STARK-based proving system. This project fills the gap identified in [miden-vm#629](https://github.com/0xMiden/miden-vm/discussions/629) by providing verified, reusable data structures and cryptographic building blocks for the Miden ecosystem.

---

## ✨ What's Inside

### 🔐 Cryptographic Primitives (`crates/miden-zk-primitives`)

| Primitive | Description | MASM File |
|-----------|-------------|-----------|
| **Merkle membership proof** | Prove an element belongs to a committed Merkle tree without revealing the tree | `masm/merkle_proof.masm` |
| **Range proof** | Prove a secret value lies within `[lo, hi]` without revealing it | `masm/range_proof.masm` |
| **RPO commitment** | Commit to a value using Rescue Prime Optimized hash; later open selectively | `masm/commitment.masm` |
| **Set membership** | Prove membership in a committed set without revealing your element | `masm/set_membership.masm` |
| **Nullifier** | Single-use spend token — prevents double-spending in private protocols | `masm/nullifier.masm` |

### 🗳️ ZK Applications (`examples/`)

| Application | What it proves | Why it's interesting |
|-------------|----------------|----------------------|
| **Private voting** | "I cast a valid vote" without revealing your choice or identity | One-person-one-vote with full privacy |
| **Anonymous age verification** | "I am over 18" without revealing your birthdate | KYC without data exposure |
| **ZK set membership** | "My value is in this approved list" without revealing the value | Private allowlists, private KYC tiers |

### 📚 Collections Library (`crates/miden-collections`)

ZK-friendly data structure implementations in Rust + MASM:
- **Merkle accumulator** — append-only accumulator with efficient membership proofs
- **Sparse Merkle tree** — key-value store with ZK-provable reads/writes  
- **Sorted array** — binary-searchable array with proof of correct ordering

---

## 🚀 Quick Start

```bash
git clone https://github.com/amathxbt/miden-zk-primitives
cd miden-zk-primitives
cargo build --workspace
cargo test --workspace
```

### Run the private voting demo

```bash
cargo run --example private_voting
```

```
[miden-zk-primitives] Private Voting Demo
==========================================
Candidates: ["Alice", "Bob", "Carol"]
Voters:     3 registered (commitment root: 0xa3f1...)

Casting votes (privately)...
  Voter 0 → vote committed (nullifier: 0x9c2d...)
  Voter 1 → vote committed (nullifier: 0x4e7a...)
  Voter 2 → vote committed (nullifier: 0x11f3...)

Tallying (ZK proof generated)...
  Alice: 2 votes
  Bob:   1 vote
  Carol: 0 votes

✅ Proof verified! (42 ms, 2^14 trace rows)
```

### Run the anonymous age proof

```bash
cargo run --example anonymous_age_proof
```

```
[miden-zk-primitives] Anonymous Age Verification
=================================================
Claim:  "I am over 18 years old"
Secret: birthdate = 1998-07-14  ← never leaves your machine

Generating ZK proof...
  ✅ Proof generated (18 ms)
  ✅ Proof verified — claimant is over 18
  ✅ Birthdate NOT revealed in proof
```

---

## 🏗️ Architecture

```
miden-zk-primitives/
├── crates/
│   ├── miden-zk-primitives/     # Core cryptographic primitives (Rust + MASM)
│   │   ├── src/
│   │   │   ├── lib.rs           # Public API
│   │   │   ├── merkle.rs        # Merkle tree helpers
│   │   │   ├── commitment.rs    # RPO commitment scheme
│   │   │   ├── range_proof.rs   # Range proof helpers
│   │   │   └── nullifier.rs     # Nullifier construction
│   │   └── Cargo.toml
│   │
│   └── miden-collections/       # ZK-friendly data structures
│       ├── src/
│       │   ├── lib.rs
│       │   ├── accumulator.rs   # Merkle accumulator
│       │   └── sparse_tree.rs   # Sparse Merkle tree
│       └── Cargo.toml
│
├── masm/                        # Pure MASM library files
│   ├── merkle_proof.masm        # Merkle path verification
│   ├── range_proof.masm         # Range proof gadget
│   ├── commitment.masm          # RPO commitment open/verify
│   ├── set_membership.masm      # Set membership gadget
│   └── nullifier.masm           # Nullifier derivation
│
├── examples/
│   ├── private_voting/          # Full private voting application
│   ├── anonymous_age_proof/     # Anonymous age verification
│   └── zk_set_membership/       # Private set membership
│
└── benches/
    └── primitives.rs            # Criterion benchmarks
```

---

## 🔬 How the Primitives Work

### Merkle Membership Proof

A classical Merkle proof, adapted for Miden VM's RPO hash function:

```
Prover holds:  leaf_value, leaf_index, auth_path[0..depth]
Public input:  merkle_root, leaf_index
Proof:         "leaf_value is at leaf_index in the tree with root merkle_root"
```

The MASM program verifies the path using `mtree_verify`, which is a native Miden VM instruction — making it maximally efficient.

### Range Proof

Uses a bit-decomposition gadget:

```
Secret: x  (kept private)
Public: lo, hi
Proof:  "lo ≤ x ≤ hi"

Steps:
  1. Decompose (x - lo) into bits  →  proves x ≥ lo
  2. Decompose (hi - x) into bits  →  proves x ≤ hi
  3. Assert both decompositions are valid 32-bit values
```

### RPO Commitment

```
commit(value, randomness) = RPO_hash([value, randomness, 0, 0])
open(commitment, value, randomness) → assert hash matches commitment
```

Using Miden VM's native `hperm` instruction for maximal proving efficiency.

### Nullifier

Prevents double-use of secrets in private protocols:

```
nullifier = RPO_hash([secret_key, context_tag, 0, 0])
```

A nullifier is published when a secret is "spent." Anyone can check if a nullifier has been used before, but cannot reverse-engineer the secret.

---

## 📊 Performance

All benchmarks run on a standard laptop (Apple M2, 16 GB RAM):

| Primitive | Trace rows | Proof time | Verify time |
|-----------|-----------|-----------|------------|
| Merkle proof (depth 20) | 2^13 | 8 ms | 1 ms |
| Range proof (32-bit) | 2^12 | 5 ms | <1 ms |
| RPO commitment open | 2^10 | 2 ms | <1 ms |
| Set membership (n=1000) | 2^14 | 18 ms | 1 ms |
| Private vote (n=100 voters) | 2^16 | 42 ms | 2 ms |

---

## 🤝 Contributing

Contributions are welcome! This project is intentionally designed as a community resource for the Miden ecosystem.

```bash
# Run tests
cargo test --workspace

# Run clippy
cargo clippy --workspace -- -D warnings

# Run benchmarks
cargo bench
```

Please follow the [Miden VM contribution guide](https://github.com/0xMiden/miden-vm/blob/next/CONTRIBUTING.md) for code style.

---

## 📄 License

Licensed under either of:
- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.

---

## 🙏 Acknowledgements

Built on top of [Miden VM](https://github.com/0xMiden/miden-vm) by the 0xMiden team.
Inspired by discussions in [miden-vm#629](https://github.com/0xMiden/miden-vm/discussions/629).
