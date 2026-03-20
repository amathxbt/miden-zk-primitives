//! Recursive SNARK: prove a chain of state transitions.
//!
//! Models Nova-style incremental verifiable computation (IVC):
//! - A step function `F(state, input) → next_state`.
//! - A proof that `n` applications of `F` transform `z₀` into `zₙ`.
//! - Each step's proof is folded into an accumulator.
//!
//! # Examples
//!
//! ```rust
//! use miden_zk_primitives::recursive::{IvcChain, StepInput};
//!
//! // Step function: state = state * 2 + input
//! fn double_add(state: u64, inp: u64) -> u64 {
//!     state.wrapping_mul(2).wrapping_add(inp)
//! }
//!
//! let mut chain = IvcChain::new(0, double_add);
//! chain.step(1);
//! chain.step(2);
//! chain.step(3);
//!
//! // z₀=0 → z₁=1 → z₂=4 → z₃=11
//! assert_eq!(chain.current_state(), 11);
//! assert!(chain.verify());
//! ```

use alloc::vec::Vec;

/// A single IVC step: state before, input, state after, and a proof hash.
#[derive(Debug, Clone)]
pub struct StepInput {
    /// State before this step.
    pub z_in: u64,
    /// Input to the step function.
    pub input: u64,
    /// State after this step.
    pub z_out: u64,
    /// Folded proof commitment.
    pub proof_hash: u64,
}

/// Proof hash: binds `(z_in, input, z_out)` together.
#[inline]
fn step_hash(z_in: u64, input: u64, z_out: u64) -> u64 {
    let x = z_in
        .wrapping_mul(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(input.wrapping_mul(0x6c62_272e_07bb_0142))
        .wrapping_add(z_out);
    x ^ (x >> 21) ^ (x << 11)
}

/// An accumulator that folds step proofs together.
#[inline]
fn fold(acc: u64, step_hash: u64) -> u64 {
    acc.wrapping_mul(0x517c_c1b7_2722_0a95)
        .wrapping_add(step_hash)
        ^ (acc >> 13)
}

/// An IVC (Incrementally Verifiable Computation) chain.
pub struct IvcChain<F>
where
    F: Fn(u64, u64) -> u64,
{
    /// Initial state `z₀`.
    pub z0: u64,
    /// Current state `zₙ`.
    current: u64,
    /// Accumulated proof.
    accumulator: u64,
    /// Step history.
    pub steps: Vec<StepInput>,
    /// The step function.
    step_fn: F,
}

impl<F> IvcChain<F>
where
    F: Fn(u64, u64) -> u64,
{
    /// Create a new chain starting from `initial_state`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::recursive::IvcChain;
    /// let chain = IvcChain::new(0u64, |s, i| s + i);
    /// assert_eq!(chain.current_state(), 0);
    /// ```
    #[must_use]
    pub fn new(initial_state: u64, step_fn: F) -> Self {
        Self {
            z0: initial_state,
            current: initial_state,
            accumulator: 0,
            steps: Vec::new(),
            step_fn,
        }
    }

    /// Apply one step with the given `input`, folding the proof.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::recursive::IvcChain;
    /// let mut chain = IvcChain::new(10u64, |s, i| s + i);
    /// chain.step(5);
    /// assert_eq!(chain.current_state(), 15);
    /// ```
    pub fn step(&mut self, input: u64) {
        let z_in = self.current;
        let z_out = (self.step_fn)(z_in, input);
        let ph = step_hash(z_in, input, z_out);
        self.accumulator = fold(self.accumulator, ph);
        self.steps.push(StepInput {
            z_in,
            input,
            z_out,
            proof_hash: ph,
        });
        self.current = z_out;
    }

    /// Current state after all applied steps.
    #[must_use]
    pub fn current_state(&self) -> u64 {
        self.current
    }

    /// Number of steps applied.
    #[must_use]
    pub fn num_steps(&self) -> usize {
        self.steps.len()
    }

    /// Verify the full IVC chain by re-executing and re-deriving the accumulator.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use miden_zk_primitives::recursive::IvcChain;
    /// let mut chain = IvcChain::new(1u64, |s, _| s.wrapping_mul(2));
    /// chain.step(0); chain.step(0); chain.step(0);
    /// assert_eq!(chain.current_state(), 8);
    /// assert!(chain.verify());
    /// ```
    #[must_use]
    pub fn verify(&self) -> bool {
        let mut state = self.z0;
        let mut acc = 0u64;
        for s in &self.steps {
            if s.z_in != state {
                return false;
            }
            let expected_out = (self.step_fn)(s.z_in, s.input);
            if s.z_out != expected_out {
                return false;
            }
            let ph = step_hash(s.z_in, s.input, s.z_out);
            if ph != s.proof_hash {
                return false;
            }
            acc = fold(acc, ph);
            state = s.z_out;
        }
        state == self.current && acc == self.accumulator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_add_chain() {
        let mut chain = IvcChain::new(0u64, |s, i| s.wrapping_mul(2).wrapping_add(i));
        chain.step(1);
        chain.step(2);
        chain.step(3);
        assert_eq!(chain.current_state(), 11);
        assert!(chain.verify());
    }

    #[test]
    fn fibonacci_like() {
        // state tracks cumulative sum
        let mut chain = IvcChain::new(0u64, |s, i| s.wrapping_add(i));
        for i in 1..=10u64 {
            chain.step(i);
        }
        assert_eq!(chain.current_state(), 55); // 1+2+…+10
        assert!(chain.verify());
    }

    #[test]
    fn empty_chain_verifies() {
        let chain = IvcChain::new(42u64, |s, i| s + i);
        assert_eq!(chain.current_state(), 42);
        assert!(chain.verify());
    }

    #[test]
    fn tampered_step_fails() {
        let mut chain = IvcChain::new(0u64, |s, i| s + i);
        chain.step(5);
        chain.step(10);
        // Tamper with the z_out of the first step
        chain.steps[0].z_out = 999;
        assert!(!chain.verify());
    }

    #[test]
    fn single_step() {
        let mut chain = IvcChain::new(7u64, |s, i| s.wrapping_mul(i));
        chain.step(6);
        assert_eq!(chain.current_state(), 42);
        assert!(chain.verify());
    }
}
