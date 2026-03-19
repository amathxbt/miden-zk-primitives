# Contributing to miden-zk-primitives

Thank you for your interest in contributing! This library aims to be a
high-quality, well-documented collection of zero-knowledge primitives for the
[Miden VM](https://github.com/0xMiden/miden-vm) ecosystem.

## Getting Started

```bash
git clone https://github.com/amathxbt/miden-zk-primitives
cd miden-zk-primitives
cargo test --all-features
```

## Guidelines

- **Tests required** for every new primitive or algorithm.
- **Documentation** – add `///` doc comments with at least one example.
- **No unsafe code** unless unavoidable and clearly justified with a `SAFETY:` comment.
- **Formatting** – run `cargo fmt` before committing.
- **Clippy** – run `cargo clippy --all-features` and fix all warnings.

## Pull Request Process

1. Fork the repo and create a feature branch.
2. Add your changes with tests and docs.
3. Ensure CI passes locally (`cargo test && cargo clippy && cargo fmt --check`).
4. Open a PR against `main` with a clear description of the change.

## Scope

This library focuses on:
- ZK-friendly cryptographic primitives (commitments, nullifiers, Merkle trees).
- Range and set-membership proofs expressed as Miden VM programs.
- Example applications demonstrating privacy-preserving patterns.

Out of scope: consensus, networking, wallet logic.
