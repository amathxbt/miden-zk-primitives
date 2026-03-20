//! Zero-Knowledge Proof (ZKP) circuit simulator.
//!
//! Models an R1CS (Rank-1 Constraint System) circuit: a system of constraints
//! of the form `(A · w) * (B · w) = (C · w)` over a 64-bit scalar field.
//! The prover supplies a witness vector `w`; the verifier checks all constraints.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::zkp::{R1CSCircuit, R1CSConstraint};
//!
//! // Prove: x * x = 9  (i.e. x = 3)
//! // Witness: [1, x, x*x] = [1, 3, 9]
//! let mut circuit = R1CSCircuit::new(3);
//! // x * x = out  =>  w[1]*w[1] = w[2]
//! circuit.add_constraint(R1CSConstraint {
//!     a: vec![(1, 1)],   // w[1]
//!     b: vec![(1, 1)],   // w[1]
//!     c: vec![(2, 1)],   // w[2]
//! });
//! let witness = vec![1, 3, 9];
//! assert!(circuit.verify(&witness));
//! ```

use alloc::vec::Vec;

use crate::error::PrimitiveError;

/// A single R1CS constraint: `(Σ aᵢ·wᵢ) * (Σ bᵢ·wᵢ) = (Σ cᵢ·wᵢ)`.
///
/// Each vector is a list of `(witness_index, coefficient)` pairs.
#[derive(Debug, Clone)]
pub struct R1CSConstraint {
    /// Left-hand linear combination.
    pub a: Vec<(usize, u64)>,
    /// Right-hand linear combination.
    pub b: Vec<(usize, u64)>,
    /// Output linear combination.
    pub c: Vec<(usize, u64)>,
}

impl R1CSConstraint {
    fn lc(terms: &[(usize, u64)], witness: &[u64]) -> u64 {
        terms.iter().fold(0u64, |acc, &(i, coef)| {
            acc.wrapping_add(coef.wrapping_mul(witness[i]))
        })
    }

    /// Check this constraint against `witness`.
    #[must_use]
    pub fn check(&self, witness: &[u64]) -> bool {
        let a = Self::lc(&self.a, witness);
        let b = Self::lc(&self.b, witness);
        let c = Self::lc(&self.c, witness);
        a.wrapping_mul(b) == c
    }
}

/// An R1CS circuit holding a set of constraints.
#[derive(Debug, Clone)]
pub struct R1CSCircuit {
    /// Number of witness variables (including the constant `1` at index 0).
    pub num_vars: usize,
    constraints: Vec<R1CSConstraint>,
}

impl R1CSCircuit {
    /// Create a new circuit with `num_vars` witness slots.
    ///
    /// By convention `witness[0]` must always equal `1`.
    #[must_use]
    pub fn new(num_vars: usize) -> Self {
        Self {
            num_vars,
            constraints: Vec::new(),
        }
    }

    /// Add a constraint to the circuit.
    pub fn add_constraint(&mut self, c: R1CSConstraint) {
        self.constraints.push(c);
    }

    /// Number of constraints.
    #[must_use]
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// Verify all constraints against `witness`.
    ///
    /// Returns `false` if any constraint fails or the witness is the wrong size.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::zkp::{R1CSCircuit, R1CSConstraint};
    /// let mut c = R1CSCircuit::new(3);
    /// c.add_constraint(R1CSConstraint { a: vec![(1,1)], b: vec![(1,1)], c: vec![(2,1)] });
    /// assert!(c.verify(&[1, 4, 16]));  // 4*4==16
    /// assert!(!c.verify(&[1, 4, 15])); // 4*4!=15
    /// ```
    #[must_use]
    pub fn verify(&self, witness: &[u64]) -> bool {
        if witness.len() != self.num_vars || witness[0] != 1 {
            return false;
        }
        self.constraints.iter().all(|c| c.check(witness))
    }

    /// Generate a succinct proof commitment (hash of all constraint evaluations).
    ///
    /// # Errors
    ///
    /// Returns [`PrimitiveError::Internal`] if the witness is invalid.
    pub fn prove(&self, witness: &[u64]) -> Result<ZKProof, PrimitiveError> {
        if !self.verify(witness) {
            return Err(PrimitiveError::Internal(
                "witness does not satisfy all constraints".into(),
            ));
        }
        // Hash witness values together for the proof commitment
        let commitment = witness.iter().enumerate().fold(0u64, |acc, (i, &w)| {
            acc.wrapping_add(w.wrapping_mul(0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 1)))
        });
        let num_constraints = self.num_constraints();
        Ok(ZKProof {
            commitment,
            num_constraints,
        })
    }
}

/// A succinct ZK proof over an R1CS circuit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZKProof {
    /// Commitment to the witness.
    pub commitment: u64,
    /// Number of satisfied constraints.
    pub num_constraints: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn square_circuit() -> (R1CSCircuit, Vec<u64>) {
        // x * x = y  →  witness = [1, x, y]
        let mut c = R1CSCircuit::new(3);
        c.add_constraint(R1CSConstraint {
            a: vec![(1, 1)],
            b: vec![(1, 1)],
            c: vec![(2, 1)],
        });
        (c, vec![1, 7, 49])
    }

    #[test]
    fn r1cs_square_verifies() {
        let (circuit, witness) = square_circuit();
        assert!(circuit.verify(&witness));
    }

    #[test]
    fn r1cs_wrong_witness_fails() {
        let (circuit, mut witness) = square_circuit();
        witness[2] = 48;
        assert!(!circuit.verify(&witness));
    }

    #[test]
    fn r1cs_multi_constraint() {
        // x*y = z  AND  z*z = w  →  witness = [1, x, y, z, w]
        let mut c = R1CSCircuit::new(5);
        c.add_constraint(R1CSConstraint {
            a: vec![(1, 1)],
            b: vec![(2, 1)],
            c: vec![(3, 1)],
        });
        c.add_constraint(R1CSConstraint {
            a: vec![(3, 1)],
            b: vec![(3, 1)],
            c: vec![(4, 1)],
        });
        // x=3, y=4, z=12, w=144
        assert!(c.verify(&[1, 3, 4, 12, 144]));
        assert!(!c.verify(&[1, 3, 4, 12, 143]));
    }

    #[test]
    fn prove_produces_proof() {
        let (circuit, witness) = square_circuit();
        let proof = circuit.prove(&witness).unwrap();
        assert_eq!(proof.num_constraints, 1);
        assert_ne!(proof.commitment, 0);
    }

    #[test]
    fn prove_invalid_witness_errors() {
        let (circuit, mut witness) = square_circuit();
        witness[2] = 0;
        assert!(circuit.prove(&witness).is_err());
    }
}
