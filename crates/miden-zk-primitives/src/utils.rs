//! Utility functions shared across primitives.

use miden_core::Felt;

/// Convert a `u64` to a `Felt` (panics if value exceeds the field modulus).
pub fn u64_to_felt(v: u64) -> Felt {
    Felt::new(v)
}

/// Convert a `Felt` to a `u64`.
pub fn felt_to_u64(f: Felt) -> u64 {
    f.as_int()
}

/// Format a `Word` as a short hex string (first 8 hex chars of first element).
pub fn word_to_short_hex(word: &miden_core::Word) -> String {
    format!("0x{:08x}", word[0].as_int() & 0xffff_ffff)
}
