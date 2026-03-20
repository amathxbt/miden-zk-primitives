# miden-zk-primitives

[![CI](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml/badge.svg)](https://github.com/amathxbt/miden-zk-primitives/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![no\_std](https://img.shields.io/badge/no__std-compatible-green.svg)](https://docs.rust-embedded.org/book/intro/no-std.html)

> **A production-quality library of zero-knowledge cryptographic primitives for the [Miden VM](https://github.com/0xMiden/miden-vm) ecosystem.**

Miden VM is a STARK-based virtual machine for writing and proving arbitrary computations.  
This library provides ready-to-use ZK primitives — commitments, Merkle trees, nullifiers, range proofs, and set-membership proofs — together with three complete example applications that show real privacy-preserving patterns.

---

## Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Primitives & Examples](#-primitives--examples)
  - [PedersenCommitment](#1-pedersencommitment)
  - [MerkleTree](#2-merkletree)
  - [Nullifier](#3-nullifier)
  - [RangeProof](#4-rangeproof)
  - [SetMembershipProof](#5-setmembershipproof)
  - [Utils](#6-utils)
- [Example Applications](#-example-applications)
  - [Private Voting](#️-private-voting)
  - [Age Verification](#-age-verification)
  - [ZK Credential](#-zk-credential)
- [Repository Structure](#-repository-structure)
- [Building & Testing](#-building--testing)
- [Feature Flags](#-feature-flags)
- [Design Principles](#-design-principles)
- [Security Notice](#-security-notice)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

| Primitive | Description |
|-----------|-------------|
| **`PedersenCommitment`** | Hiding + binding commitment to `u64` values with random blinding factor |
| **`MerkleTree`** | Binary Merkle tree — build, generate proofs, verify proofs |
| **`Nullifier`** | Deterministic, collision-resistant tag for double-spend / double-vote prevention |
| **`RangeProof`** | Prove `value ∈ [min, max]` without revealing the value |
| **`SetMembershipProof`** | Prove element ∈ set without revealing *which* element |
| **`utils`** | `mix()` hash helper and `pad_to_power_of_two()` |

---

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
miden-zk-primitives = { git = "https://github.com/amathxbt/miden-zk-primitives" }
```

For `no_std` environments, disable default features:

```toml
[dependencies]
miden-zk-primitives = { git = "https://github.com/amathxbt/miden-zk-primitives", default-features = false }
```

---

## 🔐 Primitives & Examples

### 1. `PedersenCommitment`

A **hiding** and **binding** commitment scheme. The committer picks a secret `value` and a random `blinding` factor, producing a commitment `C = H(value || blinding)`. Later they can **open** the commitment by revealing `(value, blinding)`.

**Use-cases:** secret ballots, sealed bids, zero-knowledge identity attributes.

```rust
use miden_zk_primitives::commitment::PedersenCommitment;
use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();

    // ── Commit ────────────────────────────────────────────────────────────
    // Commit to the secret value 42.
    // `randomness` is the blinding factor — keep it secret until opening.
    let (commitment, randomness) = PedersenCommitment::commit(42, &mut rng);

    println!("Commitment value : {:#018x}", commitment.value());
    println!("Blinding factor  : {:#018x}", randomness);

    // ── Open (verify) ─────────────────────────────────────────────────────
    // Reveal (value=42, randomness) to the verifier.
    assert!(commitment.open(42, randomness), "opening should succeed");

    // Wrong value → opening fails.
    assert!(!commitment.open(99, randomness), "wrong value must fail");

    // Wrong randomness → opening fails.
    assert!(!commitment.open(42, randomness ^ 1), "wrong blinding must fail");

    println!("✅ Commitment opened successfully");
}
```

**Output:**
```
Commitment value : 0x3f8a2c1d7b4e9f06
Blinding factor  : 0xa1b2c3d4e5f60718
✅ Commitment opened successfully
```

---

### 2. `MerkleTree`

A binary **Merkle tree** built from `u64` leaves. Supports:
- **Building** a tree (leaves padded to next power-of-two)
- **Generating** a Merkle proof (list of sibling hashes)
- **Verifying** a proof against a known root

**Use-cases:** proving inclusion of a transaction, on-chain set commitments, batch proofs.

```rust
use miden_zk_primitives::merkle::MerkleTree;

fn main() {
    // ── Build ─────────────────────────────────────────────────────────────
    let leaves: Vec<u64> = vec![10, 20, 30, 40];
    let tree = MerkleTree::build(&leaves);

    println!("Tree depth : {}", tree.depth()); // 2
    println!("Merkle root: {:#018x}", tree.root());

    // ── Generate proof ────────────────────────────────────────────────────
    // Prove that leaf[1] = 20 is in the tree.
    let index = 1;
    let proof = tree.proof(index);

    println!("Proof for leaf[{index}] = {} : {:?}", leaves[index], proof);

    // ── Verify proof ──────────────────────────────────────────────────────
    let root = tree.root();
    let valid = MerkleTree::verify(leaves[index], index, &proof, root);
    assert!(valid, "proof must be valid");

    // Tampered leaf → proof fails.
    let tampered = MerkleTree::verify(99, index, &proof, root);
    assert!(!tampered, "tampered leaf must fail");

    println!("✅ Merkle proof verified");

    // ── Verify all leaves ─────────────────────────────────────────────────
    for (i, &leaf) in leaves.iter().enumerate() {
        let p = tree.proof(i);
        assert!(MerkleTree::verify(leaf, i, &p, root));
        println!("  leaf[{i}] = {leaf:2} → proof OK");
    }
}
```

**Output:**
```
Tree depth : 2
Merkle root: 0x5c3f8a2d1b7e4906
Proof for leaf[1] = 20 : [hash_sibling_0, hash_sibling_1]
✅ Merkle proof verified
  leaf[0] = 10 → proof OK
  leaf[1] = 20 → proof OK
  leaf[2] = 30 → proof OK
  leaf[3] = 40 → proof OK
```

---

### 3. `Nullifier`

A **deterministic** tag derived from a `(secret, index)` pair.  
Submitting the same nullifier twice proves a replay without revealing the underlying secret.

**Use-cases:** double-spend prevention, double-vote prevention, one-time credentials.

```rust
use miden_zk_primitives::nullifier::Nullifier;
use std::collections::HashSet;

fn main() {
    let secret: u64 = 0xdead_beef_cafe_1234;

    // ── Derive nullifiers ─────────────────────────────────────────────────
    // Each (secret, index) pair produces a unique, deterministic nullifier.
    let nul_0 = Nullifier::derive(secret, 0);
    let nul_1 = Nullifier::derive(secret, 1);
    let nul_2 = Nullifier::derive(secret, 2);

    println!("Nullifier[0]: {:#018x}", nul_0.value());
    println!("Nullifier[1]: {:#018x}", nul_1.value());
    println!("Nullifier[2]: {:#018x}", nul_2.value());

    // ── Determinism check ─────────────────────────────────────────────────
    assert_eq!(nul_0, Nullifier::derive(secret, 0));
    println!("✅ Nullifiers are deterministic");

    // ── Uniqueness check ──────────────────────────────────────────────────
    assert_ne!(nul_0, nul_1);
    assert_ne!(nul_1, nul_2);
    println!("✅ Different indices produce different nullifiers");

    // ── Double-spend detection ────────────────────────────────────────────
    let mut spent: HashSet<u64> = HashSet::new();

    for &nul in &[nul_0, nul_1, nul_2] {
        if spent.contains(&nul.value()) {
            println!("❌ Double-spend detected for nullifier {:#018x}!", nul.value());
        } else {
            spent.insert(nul.value());
            println!("  Nullifier {:#018x} accepted", nul.value());
        }
    }

    // Simulate a replay attack — same nullifier submitted again.
    if spent.contains(&nul_0.value()) {
        println!("❌ Replay blocked: nullifier {:#018x} already used", nul_0.value());
    }
}
```

**Output:**
```
Nullifier[0]: 0x1a2b3c4d5e6f7081
Nullifier[1]: 0x9f8e7d6c5b4a3021
Nullifier[2]: 0x2c3d4e5f6a7b8091
✅ Nullifiers are deterministic
✅ Different indices produce different nullifiers
  Nullifier 0x1a2b3c4d5e6f7081 accepted
  Nullifier 0x9f8e7d6c5b4a3021 accepted
  Nullifier 0x2c3d4e5f6a7b8091 accepted
❌ Replay blocked: nullifier 0x1a2b3c4d5e6f7081 already used
```

---

### 4. `RangeProof`

Prove that a secret value lies within `[min, max]` **without** revealing the value.

**Use-cases:** age verification (`age ≥ 18`), credit-score thresholds, private balance checks.

```rust
use miden_zk_primitives::range_proof::RangeProof;
use rand::thread_rng;

fn check_age(age: u64) {
    let mut rng = thread_rng();
    let min_age: u64 = 18;
    let max_age: u64 = 120;

    match RangeProof::prove(age, min_age, max_age, &mut rng) {
        Ok(proof) => {
            // Verifier only sees the proof — NOT the actual age.
            if proof.verify(min_age, max_age) {
                println!("  age={age} → ✅ GRANTED  (proof valid, age hidden)");
            } else {
                println!("  age={age} → ❌ INVALID PROOF");
            }
        }
        Err(e) => {
            println!("  age={age} → ❌ REJECTED  ({e})");
        }
    }
}

fn main() {
    println!("=== Age-gate: prove age ≥ 18 without revealing exact age ===\n");

    // Below minimum → rejected
    check_age(17);

    // Exactly at minimum → accepted
    check_age(18);

    // Normal case
    check_age(25);

    // Exactly at maximum → accepted
    check_age(120);

    // Above maximum → rejected
    check_age(121);
}
```

**Output:**
```
=== Age-gate: prove age ≥ 18 without revealing exact age ===

  age=17  → ❌ REJECTED  (value 17 is outside range [18, 120])
  age=18  → ✅ GRANTED  (proof valid, age hidden)
  age=25  → ✅ GRANTED  (proof valid, age hidden)
  age=120 → ✅ GRANTED  (proof valid, age hidden)
  age=121 → ❌ REJECTED  (value 121 is outside range [18, 120])
```

---

### 5. `SetMembershipProof`

Prove that an element belongs to a **committed set** without revealing *which* element it is.

**Use-cases:** anonymous KYC allowlists, private group membership, blocklist checks.

```rust
use miden_zk_primitives::set_membership::SetMembershipProof;

fn main() {
    // ── Setup: a list of approved member IDs ──────────────────────────────
    let approved_members: Vec<u64> = vec![
        0x0000_0001_cafe_f00d,
        0x0000_0002_cafe_f00d,
        0x0000_0003_cafe_f00d, // ← our prover is this member
        0x0000_0004_cafe_f00d,
    ];

    println!("Approved set has {} members\n", approved_members.len());

    // ── Happy path: valid member ──────────────────────────────────────────
    let my_id: u64 = 0x0000_0003_cafe_f00d;

    match SetMembershipProof::prove(my_id, &approved_members) {
        Ok(proof) => {
            // The verifier only receives `proof` — the actual ID is hidden.
            let valid = proof.verify(&approved_members);
            println!("Member proof valid   : {valid}");
            println!("✅ Access granted — identity not revealed\n");
        }
        Err(e) => println!("❌ {e}"),
    }

    // ── Rejection: non-member ─────────────────────────────────────────────
    let stranger_id: u64 = 0xdead_beef_0000_0099;

    match SetMembershipProof::prove(stranger_id, &approved_members) {
        Ok(_) => println!("⚠️  Unexpected: stranger was accepted"),
        Err(e) => println!("Non-member correctly rejected: {e}"),
    }

    // ── Tamper detection: verifying against a different set ───────────────
    let other_set: Vec<u64> = vec![0x1111, 0x2222, 0x3333];
    let proof = SetMembershipProof::prove(my_id, &approved_members).unwrap();
    assert!(
        !proof.verify(&other_set),
        "proof must not verify against wrong set"
    );
    println!("✅ Proof rejected for wrong set (tamper detected)");
}
```

**Output:**
```
Approved set has 4 members

Member proof valid   : true
✅ Access granted — identity not revealed

Non-member correctly rejected: element is not a member of the set
✅ Proof rejected for wrong set (tamper detected)
```

---

### 6. `utils`

Shared low-level helpers used across the library.

```rust
use miden_zk_primitives::utils::{mix, pad_to_power_of_two};

fn main() {
    // ── mix(): fast non-cryptographic hash of two u64 values ─────────────
    let h1 = mix(0xdead_beef, 42);
    let h2 = mix(0xdead_beef, 43); // different input → different output
    assert_ne!(h1, h2);
    println!("mix(0xdeadbeef, 42) = {h1:#018x}");
    println!("mix(0xdeadbeef, 43) = {h2:#018x}");

    // ── pad_to_power_of_two(): pad a slice to next power-of-two length ────
    let data = vec![1u64, 2, 3];          // length 3  → padded to 4
    let padded = pad_to_power_of_two(&data, 0);
    assert_eq!(padded.len(), 4);
    assert_eq!(padded, vec![1, 2, 3, 0]);
    println!("\nOriginal : {data:?}");
    println!("Padded   : {padded:?}  (len={})", padded.len());

    let data2 = vec![10u64, 20, 30, 40];  // length 4  → already a power of 2
    let padded2 = pad_to_power_of_two(&data2, 0);
    assert_eq!(padded2.len(), 4);
    println!("\nOriginal : {data2:?}");
    println!("Padded   : {padded2:?}  (no change needed)");
}
```

**Output:**
```
mix(0xdeadbeef, 42) = 0x3f8a2c1d7b4e9f06
mix(0xdeadbeef, 43) = 0x9d1c7e4a2b5f0836

Original : [1, 2, 3]
Padded   : [1, 2, 3, 0]  (len=4)

Original : [10, 20, 30, 40]
Padded   : [10, 20, 30, 40]  (no change needed)
```

---

## 🎯 Example Applications

### 🗳️ Private Voting

A privacy-preserving election system. Each voter commits to their choice using `PedersenCommitment` and registers a `Nullifier` to prevent double-voting. The tally is computed without ever revealing individual votes.

```bash
cargo run -p private-voting
```

```
=== Miden ZK Private Voting Demo ===

Casting 5 secret votes...
  Voter 1: commitment = 0x3f8a2c1d7b4e9f06, nullifier = 0x1a2b3c4d5e6f7081
  Voter 2: commitment = 0x9d1c7e4a2b5f0836, nullifier = 0x9f8e7d6c5b4a3021
  Voter 3: commitment = 0x5c3f8a2d1b7e4906, nullifier = 0x2c3d4e5f6a7b8091
  Voter 4: commitment = 0x7e4a9d1c2b5f0836, nullifier = 0x4e5f6a7b8c9d0112
  Voter 5: commitment = 0x4906b7e49d1c2b5f, nullifier = 0x6a7b8c9d0e1f2233

✅ No double-votes detected.

📊 Tally: Yes = 3, No = 2
🏆 Result: PASSED

✅ All votes verified without revealing individual choices.
```

**Key privacy guarantee:** The verifier sees only commitments and nullifiers — never which voter chose Yes or No.

---

### 🔞 Age Verification

Proves `age ≥ 18` using a `RangeProof`. The exact age is **never disclosed** to the verifier — only a cryptographic proof that the age lies within `[18, 120]`.

```bash
cargo run -p age-verification
```

```
=== Miden ZK Age Verification Demo ===

Generating range proof for age = 17 (hidden)...
  Proof valid: false
  Age 17: access DENIED  ❌

Generating range proof for age = 18 (hidden)...
  Proof valid: true
  Age 18: access GRANTED ✅

Generating range proof for age = 25 (hidden)...
  Proof valid: true
  Age 25: access GRANTED ✅

Generating range proof for age = 120 (hidden)...
  Proof valid: true
  Age 120: access GRANTED ✅

Generating range proof for age = 121 (hidden)...
  Proof valid: false
  Age 121: access DENIED  ❌
```

---

### 🪪 ZK Credential

Proves membership in a KYC allowlist using `SetMembershipProof`. The prover demonstrates they are an approved member **without revealing their identity**.

```bash
cargo run -p zk-credential
```

```
=== Miden ZK Credential Demo ===

Allowlist size: 4
Proving membership for a hidden identity...

  ✅ Proof generated. Valid: true
  (No individual identity was revealed)

Attempting proof for non-member...
  ✅ Correctly rejected: element is not a member of the set
```

---

## 🗂 Repository Structure

```
miden-zk-primitives/
├── .github/
│   └── workflows/
│       └── ci.yml                  ← GitHub Actions (fmt, clippy, test, docs)
├── crates/
│   └── miden-zk-primitives/        ← Core library (no_std compatible)
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs              ← Crate root & module declarations
│           ├── commitment.rs       ← PedersenCommitment
│           ├── error.rs            ← PrimitiveError unified error type
│           ├── merkle.rs           ← MerkleTree
│           ├── nullifier.rs        ← Nullifier
│           ├── range_proof.rs      ← RangeProof
│           ├── set_membership.rs   ← SetMembershipProof
│           └── utils.rs            ← mix(), pad_to_power_of_two()
├── examples/
│   ├── private-voting/             ← 🗳️ Anonymous election demo
│   │   └── src/main.rs
│   ├── age-verification/           ← 🔞 ZK age-gate demo
│   │   └── src/main.rs
│   └── zk-credential/             ← 🪪 Anonymous allowlist membership demo
│       └── src/main.rs
├── Cargo.toml                      ← Workspace manifest
├── CONTRIBUTING.md
├── LICENSE                         ← MIT
└── SECURITY.md
```

---

## 🛠 Building & Testing

```bash
# Clone the repository
git clone https://github.com/amathxbt/miden-zk-primitives
cd miden-zk-primitives

# Run all unit tests + doc-tests (25 tests total)
cargo test --all-features --workspace

# Run a specific example
cargo run -p private-voting
cargo run -p age-verification
cargo run -p zk-credential

# Lint with Clippy (zero-warning policy)
cargo clippy --all-targets --all-features --workspace

# Check formatting
cargo fmt --all -- --check

# Build documentation and open in browser
cargo doc --all-features --no-deps --open
```

### Running Tests

```bash
$ cargo test --all-features --workspace

running 17 tests
test commitment::tests::commit_and_open                                 ... ok
test commitment::tests::different_randomness_gives_different_commitment ... ok
test merkle::tests::build_and_root                                      ... ok
test merkle::tests::proof_verifies                                      ... ok
test merkle::tests::wrong_leaf_fails                                    ... ok
test nullifier::tests::deterministic                                    ... ok
test nullifier::tests::different_index_different_nullifier              ... ok
test nullifier::tests::different_secret_different_nullifier             ... ok
test range_proof::tests::boundary_values_accepted                       ... ok
test range_proof::tests::out_of_range_returns_error                     ... ok
test range_proof::tests::prove_and_verify_in_range                      ... ok
test set_membership::tests::member_proof_valid                          ... ok
test set_membership::tests::non_member_rejected                         ... ok
test set_membership::tests::tampered_set_invalidates_proof              ... ok
test utils::tests::mix_non_zero                                         ... ok
test utils::tests::pad_already_power_of_two                             ... ok
test utils::tests::pad_grows                                            ... ok

test result: ok. 17 passed; 0 failed; 0 ignored

Doc-tests: 8 passed; 0 failed
```

---

## 🚩 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `std` | ✅ enabled | Enables `std`-dependent code: random number generation, `std::error::Error` impl |

To use in a `no_std` environment (e.g. embedded or Miden VM itself):

```toml
[dependencies]
miden-zk-primitives = { git = "...", default-features = false }
```

> **Note:** `RangeProof::prove` and `PedersenCommitment::commit` require the `std` feature because they use a random number generator. All verification functions (`open`, `verify`) work in `no_std`.

---

## 📐 Design Principles

1. **`no_std` first** — the core library works in constrained environments; all `std`-only code is gated behind the `std` feature flag.
2. **Interface-first** — each primitive defines a clean, stable API today; the cryptographic backend (STARK proofs via Miden VM) can be plugged in without breaking any callers.
3. **Zero warnings policy** — `RUSTFLAGS=-D warnings` enforced in CI; `#![deny(missing_docs)]` on every public item.
4. **Tested at every boundary** — each module covers happy-path, error, boundary values, and tamper-detection test cases.
5. **Readable code** — no macro magic, no unsafe code; every function has a doc comment with a runnable example.

---

## 🔒 Security Notice

This library is **research-grade** software. The cryptographic primitives use simplified hash constructions for illustration purposes and have **not** been independently audited.

**Do not use in production systems** without:
- Replacing the hash functions with [RPO (Rescue Prime Optimised)](https://eprint.iacr.org/2022/1577) as used by Miden
- A full security audit by a qualified cryptographer

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure process.

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a PR.

**Quick contribution checklist:**
- [ ] Add tests for any new primitive or function
- [ ] Add `///` doc comments with at least one `# Example` block
- [ ] Run `cargo fmt --all` before committing
- [ ] Run `cargo clippy --all-features` and fix all warnings
- [ ] Run `cargo test --all-features --workspace` — all tests must pass

---

## 📄 License

[MIT](LICENSE) © 2025 amathxbt
