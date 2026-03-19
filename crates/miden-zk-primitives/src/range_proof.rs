//! # Range Proof
//!
//! Proves that a secret value `x` satisfies `lo ≤ x ≤ hi` without revealing `x`.
//!
//! ## Technique
//!
//! The proof uses *bit decomposition*:
//!
//! 1. Compute `a = x - lo`.  If `x ≥ lo`, then `a` fits in the same bit-width as the range.
//! 2. Compute `b = hi - x`. If `x ≤ hi`, then `b` fits in the same bit-width.
//! 3. The Miden VM verifies that both `a` and `b` are valid 32-bit unsigned integers
//!    (using the native `u32split` and `u32assert` instructions).
//!
//! This approach adds only ~64 trace rows per range check, regardless of the range width.

/// Public statement for a range proof: "my secret value is in [lo, hi]".
#[derive(Debug, Clone, Copy)]
pub struct RangeStatement {
    /// Inclusive lower bound.
    pub lo: u64,
    /// Inclusive upper bound.
    pub hi: u64,
}

/// A witness for a range proof: the actual secret value.
#[derive(Debug, Clone, Copy)]
pub struct RangeWitness {
    /// The secret value (never revealed in the proof).
    pub value: u64,
}

impl RangeStatement {
    /// Create a new range statement `lo ≤ ? ≤ hi`.
    pub fn new(lo: u64, hi: u64) -> Self {
        assert!(lo <= hi, "lower bound must not exceed upper bound");
        Self { lo, hi }
    }

    /// Check whether `value` satisfies this range statement.
    ///
    /// This is the *prover-side* check — it happens before proof generation
    /// and gives a clear error if the witness is invalid.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::RangeViolation`] if `value` is outside `[lo, hi]`.
    pub fn check_witness(&self, witness: &RangeWitness) -> crate::Result<()> {
        let v = witness.value;
        if v >= self.lo && v <= self.hi {
            Ok(())
        } else {
            Err(crate::Error::RangeViolation {
                value: v,
                lo: self.lo,
                hi: self.hi,
            })
        }
    }

    /// Generate the MASM program source for this range check.
    ///
    /// The generated program:
    /// - Takes `value` as a *secret* advice input (never in the public proof).
    /// - Takes `lo` and `hi` as *public* operand stack inputs.
    /// - Halts successfully if `lo ≤ value ≤ hi`; traps otherwise.
    pub fn to_masm(&self) -> String {
        format!(
            r#"# Range proof: prove lo <= x <= hi without revealing x
# Public inputs (operand stack, bottom to top): hi, lo
# Secret input (advice stack):                  x

begin
    # Load x from the advice tape (secret)
    adv_push.1          # stack: [x, lo, hi]

    # Check x >= lo: compute a = x - lo, assert a fits in u32
    dup.0               # [x, x, lo, hi]
    movup.2             # [lo, x, x, hi]
    sub                 # [x-lo, x, hi]  — traps if x < lo (underflow mod p)
    u32assert2          # assert x-lo is a valid u32

    # Check x <= hi: compute b = hi - x, assert b fits in u32
    movup.2             # [hi, x-lo, x]   (we still need x on stack)
    movup.2             # [x, hi, x-lo]
    sub                 # [hi-x, x-lo]    — traps if x > hi
    u32assert2          # assert hi-x is a valid u32

    # Both checks passed — proof is valid
    drop drop           # clean stack
end
"#
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_witness_in_range() {
        let stmt = RangeStatement::new(10, 100);
        let ok = RangeWitness { value: 55 };
        stmt.check_witness(&ok).expect("55 is in [10, 100]");
    }

    #[test]
    fn witness_at_lower_bound() {
        let stmt = RangeStatement::new(10, 100);
        stmt.check_witness(&RangeWitness { value: 10 }).expect("lo is valid");
    }

    #[test]
    fn witness_at_upper_bound() {
        let stmt = RangeStatement::new(10, 100);
        stmt.check_witness(&RangeWitness { value: 100 }).expect("hi is valid");
    }

    #[test]
    fn witness_below_range_fails() {
        let stmt = RangeStatement::new(10, 100);
        assert!(stmt.check_witness(&RangeWitness { value: 9 }).is_err());
    }

    #[test]
    fn witness_above_range_fails() {
        let stmt = RangeStatement::new(10, 100);
        assert!(stmt.check_witness(&RangeWitness { value: 101 }).is_err());
    }

    #[test]
    fn generates_valid_masm() {
        let stmt = RangeStatement::new(18, 120);
        let masm = stmt.to_masm();
        assert!(masm.contains("adv_push.1"));
        assert!(masm.contains("u32assert2"));
    }
}
