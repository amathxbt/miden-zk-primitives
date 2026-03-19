//! Range proof over `u64` values.
//!
//! In a full Miden VM integration the proof would be generated and verified as
//! a STARK proof. Here we implement the *interface* so applications compile and
//! tests pass; the cryptographic backend can be swapped in later.

use crate::error::PrimitiveError;
#[cfg(feature = "std")]
use rand::Rng;

/// A (simulated) range proof attesting that a committed value lies in `[min, max]`.
#[derive(Debug, Clone)]
pub struct RangeProof {
    /// The lower bound used during proving.
    min: u64,
    /// The upper bound used during proving.
    max: u64,
}

impl RangeProof {
    /// Create a range proof that `value` is in `[min, max]`.
    ///
    /// Returns `Err` if `value` is outside the range.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "std")] {
    /// use miden_zk_primitives::range_proof::RangeProof;
    /// use rand::thread_rng;
    /// let proof = RangeProof::prove(25, 18, 120, &mut thread_rng()).unwrap();
    /// assert!(proof.verify(18, 120));
    /// # }
    /// ```
    #[cfg(feature = "std")]
    pub fn prove<R: Rng>(
        value: u64,
        min: u64,
        max: u64,
        rng: &mut R,
    ) -> Result<Self, PrimitiveError> {
        if value < min || value > max {
            return Err(PrimitiveError::OutOfRange { value, min, max });
        }
        // Consume randomness so the signature matches a real prover.
        let _randomness: u64 = rng.gen();
        Ok(Self { min, max })
    }

    /// Verify the proof against the same `[min, max]` range.
    ///
    /// Returns `true` if the proof is valid.
    #[must_use]
    pub fn verify(&self, min: u64, max: u64) -> bool {
        // In a real implementation this checks the STARK proof.
        self.min == min && self.max == max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "std")]
    use rand::thread_rng;

    #[test]
    #[cfg(feature = "std")]
    fn prove_and_verify_in_range() {
        let mut rng = thread_rng();
        let proof = RangeProof::prove(42, 0, 100, &mut rng).unwrap();
        assert!(proof.verify(0, 100));
    }

    #[test]
    #[cfg(feature = "std")]
    fn out_of_range_returns_error() {
        let mut rng = thread_rng();
        let err = RangeProof::prove(200, 0, 100, &mut rng).unwrap_err();
        assert_eq!(
            err,
            PrimitiveError::OutOfRange {
                value: 200,
                min: 0,
                max: 100
            }
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn boundary_values_accepted() {
        let mut rng = thread_rng();
        assert!(RangeProof::prove(0, 0, 100, &mut rng)
            .unwrap()
            .verify(0, 100));
        assert!(RangeProof::prove(100, 0, 100, &mut rng)
            .unwrap()
            .verify(0, 100));
    }
}
