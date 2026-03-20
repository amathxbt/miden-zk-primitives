# Changelog

All notable changes to this project are documented here.

## [0.2.0] — 2026-03-20

### Added
- **100% Miden VM** — all ZK primitives use real `miden_vm::prove` / `miden_vm::verify`
- `commitment` — RPO hash commitment using `hperm`
- `nullifier` — spend-once nullifier using `hperm`
- `range_proof` — native `u32gte` / `u32lte` range checks
- `schnorr` — Schnorr-like signature verification using `u32wrapping_mul`
- `accumulator` — membership accumulator using `u32wrapping_mul`
- `merkle` — Merkle membership using native `mtree_verify`
- `set_membership` — set membership using `mtree_verify`
- Five example applications: `private-voting`, `age-verification`, `zk-credential`,
  `schnorr-sig`, `accumulator`
- Full CI pipeline: Rustfmt, Clippy (`-D warnings`), Tests, Build Examples, Docs
- `ProofBundle` type — serialised STARK proof + stack outputs

### Changed
- Removed all non-Miden-VM code (pure-Rust R1CS, Groth16, Bulletproof, Poseidon
  simulations) — this library is exclusively Miden VM STARK proofs
- Cleaned up `utils.rs` — single `stack_truncated(16)` call (was redundant double call)

## [0.1.0] — 2026-03-19

- Initial release with basic ZK primitive stubs
