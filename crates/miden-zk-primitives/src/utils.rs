//! Utility functions used across the library.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::utils::{felt_to_bits, bits_to_felt};
//!
//! let bits = felt_to_bits(42, 8);
//! assert_eq!(bits_to_felt(&bits), 42);
//! ```

use alloc::vec::Vec;

/// Decompose `value` into `num_bits` little-endian bits.
///
/// If `value` requires more than `num_bits` bits the higher bits are silently
/// truncated.
///
/// # Examples
///
/// ```rust
/// use miden_zk_primitives::utils::felt_to_bits;
/// let bits = felt_to_bits(5, 4); // 5 = 0b0101
/// assert_eq!(bits, vec![1, 0, 1, 0]);
/// ```
#[must_use]
pub fn felt_to_bits(value: u64, num_bits: usize) -> Vec<u64> {
    (0..num_bits).map(|i| (value >> i) & 1).collect()
}

/// Reconstruct a field element from little-endian bits.
///
/// # Examples
///
/// ```rust
/// use miden_zk_primitives::utils::bits_to_felt;
/// assert_eq!(bits_to_felt(&[1, 0, 1, 0]), 5);
/// ```
#[must_use]
pub fn bits_to_felt(bits: &[u64]) -> u64 {
    bits.iter()
        .enumerate()
        .fold(0u64, |acc, (i, &b)| acc | (b << i))
}

/// Pad `values` to the next power of two by appending zeros.
///
/// # Examples
///
/// ```rust
/// use miden_zk_primitives::utils::pad_to_power_of_two;
/// let v = pad_to_power_of_two(vec![1u64, 2, 3]);
/// assert_eq!(v.len(), 4);
/// ```
#[must_use]
pub fn pad_to_power_of_two(mut values: Vec<u64>) -> Vec<u64> {
    let n = values.len().next_power_of_two();
    values.resize(n, 0);
    values
}

/// A domain-separated hash of two 64-bit values.
///
/// # Examples
///
/// ```rust
/// use miden_zk_primitives::utils::hash_two;
/// let h = hash_two(1, 2);
/// assert_ne!(h, hash_two(2, 1)); // not symmetric
/// ```
#[must_use]
pub fn hash_two(a: u64, b: u64) -> u64 {
    let x = a.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(b);
    x ^ (x >> 30) ^ (x << 13)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_roundtrip() {
        for v in [0u64, 1, 42, 255, u64::MAX >> 1] {
            let bits = felt_to_bits(v, 64);
            assert_eq!(bits_to_felt(&bits), v);
        }
    }

    #[test]
    fn pad_length() {
        assert_eq!(pad_to_power_of_two(vec![1, 2, 3]).len(), 4);
        assert_eq!(pad_to_power_of_two(vec![1, 2, 3, 4]).len(), 4);
        assert_eq!(pad_to_power_of_two(vec![1]).len(), 1);
    }

    #[test]
    fn hash_two_asymmetric() {
        assert_ne!(hash_two(1, 2), hash_two(2, 1));
    }
}
