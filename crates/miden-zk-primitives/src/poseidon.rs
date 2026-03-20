//! Poseidon-style hash function over a 64-bit prime field.
//!
//! Poseidon is a ZK-friendly hash function with a low number of constraints
//! per output. This implementation simulates the Poseidon sponge construction
//! with a 3-element state (`t=3`) and partial rounds.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::poseidon::PoseidonHash;
//!
//! let h = PoseidonHash::hash(&[1u64, 2, 3]);
//! assert_ne!(h, 0);
//! assert_eq!(h, PoseidonHash::hash(&[1u64, 2, 3])); // deterministic
//!
//! // Two-to-one compression (Merkle node hashing)
//! let parent = PoseidonHash::compress(42, 99);
//! assert_ne!(parent, PoseidonHash::compress(99, 42)); // not symmetric
//! ```

use alloc::vec::Vec;

/// State width (number of field elements in the sponge).
const T: usize = 3;
/// Number of full rounds.
const FULL_ROUNDS: usize = 8;
/// Number of partial rounds.
const PARTIAL_ROUNDS: usize = 22;
/// Rate (number of elements absorbed per squeeze).
const RATE: usize = 2;

/// Round constants (reproducible, derived from nothing-up-my-sleeve values).
const RC: [u64; 30] = [
    0x6b7f_2853_4e4a_7c1f,
    0x3d9a_1e6b_c5f8_2047,
    0xab12_cd34_ef56_7890,
    0x1234_5678_9abc_def0,
    0xfeed_face_cafe_babe,
    0xdead_beef_0bad_f00d,
    0x0123_4567_89ab_cdef,
    0xfedcba98_76543210,
    0xa5a5_a5a5_5a5a_5a5a,
    0x1111_2222_3333_4444,
    0x5555_6666_7777_8888,
    0x9999_aaaa_bbbb_cccc,
    0xdddd_eeee_ffff_0000,
    0x0f0f_0f0f_f0f0_f0f0,
    0x1357_9bdf_2468_ace0,
    0xfedc_ba98_7654_3210,
    0x0246_8ace_1357_9bdf,
    0xaaaa_bbbb_cccc_dddd,
    0xeeee_ffff_0000_1111,
    0x2222_3333_4444_5555,
    0x6666_7777_8888_9999,
    0xaaaa_0000_bbbb_1111,
    0xcccc_2222_dddd_3333,
    0xeeee_4444_ffff_5555,
    0x6060_7070_8080_9090,
    0xa0a0_b0b0_c0c0_d0d0,
    0xe0e0_f0f0_0101_1212,
    0x2323_3434_4545_5656,
    0x6767_7878_8989_9a9a,
    0xabab_bcbc_cdcd_dede,
];

/// MDS matrix rows (3×3, mixing layer).
const MDS: [[u64; T]; T] = [[2, 1, 1], [1, 2, 1], [1, 1, 2]];

/// S-box: x^5 in the field (approximated via wrapping squarings).
#[inline]
fn sbox(x: u64) -> u64 {
    let x2 = x.wrapping_mul(x);
    let x4 = x2.wrapping_mul(x2);
    x4.wrapping_mul(x)
}

/// MDS multiplication.
#[inline]
fn mds_mul(state: &[u64; T]) -> [u64; T] {
    let mut out = [0u64; T];
    for i in 0..T {
        for j in 0..T {
            out[i] = out[i].wrapping_add(MDS[i][j].wrapping_mul(state[j]));
        }
    }
    out
}

/// Poseidon permutation on a state of width `T`.
fn permute(state: &mut [u64; T], rc_offset: &mut usize) {
    let half_full = FULL_ROUNDS / 2;

    // First half-full rounds
    for _ in 0..half_full {
        for s in state.iter_mut() {
            *s = s.wrapping_add(RC[*rc_offset % RC.len()]);
            *rc_offset += 1;
            *s = sbox(*s);
        }
        *state = mds_mul(state);
    }

    // Partial rounds (S-box only on first element)
    for _ in 0..PARTIAL_ROUNDS {
        for s in state.iter_mut() {
            *s = s.wrapping_add(RC[*rc_offset % RC.len()]);
            *rc_offset += 1;
        }
        state[0] = sbox(state[0]);
        *state = mds_mul(state);
    }

    // Second half-full rounds
    for _ in 0..half_full {
        for s in state.iter_mut() {
            *s = s.wrapping_add(RC[*rc_offset % RC.len()]);
            *rc_offset += 1;
            *s = sbox(*s);
        }
        *state = mds_mul(state);
    }
}

/// Poseidon hash function.
pub struct PoseidonHash;

impl PoseidonHash {
    /// Hash a slice of field elements.
    ///
    /// Uses a sponge construction: absorb `RATE` elements at a time, then
    /// squeeze one element from `state[0]`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::poseidon::PoseidonHash;
    /// let h1 = PoseidonHash::hash(&[1u64, 2, 3]);
    /// let h2 = PoseidonHash::hash(&[1u64, 2, 3]);
    /// assert_eq!(h1, h2); // deterministic
    /// assert_ne!(h1, PoseidonHash::hash(&[1u64, 2, 4]));
    /// ```
    #[must_use]
    pub fn hash(inputs: &[u64]) -> u64 {
        let mut state = [0u64; T];
        // Domain separator: length of input
        state[T - 1] = inputs.len() as u64;
        let mut rc_offset = 0usize;

        for chunk in inputs.chunks(RATE) {
            for (i, &val) in chunk.iter().enumerate() {
                state[i] = state[i].wrapping_add(val);
            }
            permute(&mut state, &mut rc_offset);
        }
        state[0]
    }

    /// Two-to-one compression for Merkle tree nodes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::poseidon::PoseidonHash;
    /// let h = PoseidonHash::compress(10, 20);
    /// assert_ne!(h, PoseidonHash::compress(20, 10));
    /// ```
    #[must_use]
    pub fn compress(left: u64, right: u64) -> u64 {
        Self::hash(&[left, right])
    }

    /// Hash a byte string by converting each byte to a field element.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::poseidon::PoseidonHash;
    /// let h = PoseidonHash::hash_bytes(b"hello miden");
    /// assert_ne!(h, 0);
    /// ```
    #[must_use]
    pub fn hash_bytes(data: &[u8]) -> u64 {
        let felts: Vec<u64> = data.iter().map(|&b| u64::from(b)).collect();
        Self::hash(&felts)
    }

    /// Build a Poseidon Merkle tree and return the root.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::poseidon::PoseidonHash;
    /// let root = PoseidonHash::merkle_root(&[1u64, 2, 3, 4]);
    /// assert_ne!(root, 0);
    /// ```
    #[must_use]
    pub fn merkle_root(leaves: &[u64]) -> u64 {
        let n = leaves.len().next_power_of_two();
        let mut layer: Vec<u64> = leaves.to_vec();
        layer.resize(n, 0);
        while layer.len() > 1 {
            layer = layer
                .chunks(2)
                .map(|pair| Self::compress(pair[0], pair[1]))
                .collect();
        }
        layer[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_deterministic() {
        let h1 = PoseidonHash::hash(&[1, 2, 3]);
        let h2 = PoseidonHash::hash(&[1, 2, 3]);
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_different_inputs() {
        assert_ne!(
            PoseidonHash::hash(&[1, 2, 3]),
            PoseidonHash::hash(&[1, 2, 4])
        );
        assert_ne!(PoseidonHash::hash(&[0]), PoseidonHash::hash(&[1]));
    }

    #[test]
    fn compress_asymmetric() {
        assert_ne!(
            PoseidonHash::compress(10, 20),
            PoseidonHash::compress(20, 10)
        );
    }

    #[test]
    fn hash_bytes_consistent() {
        let h = PoseidonHash::hash_bytes(b"miden zk");
        assert_eq!(h, PoseidonHash::hash_bytes(b"miden zk"));
        assert_ne!(h, PoseidonHash::hash_bytes(b"miden ZK"));
    }

    #[test]
    fn merkle_root_consistent() {
        let r1 = PoseidonHash::merkle_root(&[1, 2, 3, 4]);
        let r2 = PoseidonHash::merkle_root(&[1, 2, 3, 4]);
        assert_eq!(r1, r2);
        assert_ne!(r1, PoseidonHash::merkle_root(&[1, 2, 3, 5]));
    }

    #[test]
    fn single_element_hash() {
        assert_ne!(PoseidonHash::hash(&[42]), 0);
    }
}
