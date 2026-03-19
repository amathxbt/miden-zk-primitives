//! Shared utilities and helper functions.

/// Mix two `u64` values with a fast, non-cryptographic hash.
///
/// Useful for building larger hash functions from smaller components.
///
/// # Example
/// ```
/// use miden_zk_primitives::utils::mix;
/// let h = mix(0xdeadbeef, 42);
/// assert_ne!(h, 0);
/// ```
#[must_use]
pub fn mix(a: u64, b: u64) -> u64 {
    a.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(b.wrapping_mul(0x6c62_272e_07bb_0142))
}

/// Pad `data` to the next power-of-two length by appending `pad_value`.
///
/// # Example
/// ```
/// use miden_zk_primitives::utils::pad_to_power_of_two;
/// let padded = pad_to_power_of_two(&[1u64, 2, 3], 0);
/// assert_eq!(padded.len(), 4);
/// ```
#[must_use]
pub fn pad_to_power_of_two(data: &[u64], pad_value: u64) -> alloc::vec::Vec<u64> {
    let n = data.len().next_power_of_two();
    let mut v = data.to_vec();
    v.resize(n, pad_value);
    v
}

// `alloc` is available via the standard prelude when `std` is enabled;
// for `no_std` builds we need an explicit extern.
#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix_non_zero() {
        assert_ne!(mix(1, 2), 0);
    }

    #[test]
    fn pad_already_power_of_two() {
        let v = pad_to_power_of_two(&[1u64, 2, 3, 4], 0);
        assert_eq!(v.len(), 4);
    }

    #[test]
    fn pad_grows() {
        let v = pad_to_power_of_two(&[1u64, 2, 3], 0);
        assert_eq!(v.len(), 4);
        assert_eq!(v[3], 0);
    }
}
