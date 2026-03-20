//! Error types shared across all ZK primitives.

use alloc::string::String;
use core::fmt;

/// Unified error type for all primitive operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrimitiveError {
    /// A value fell outside the permitted range.
    OutOfRange {
        /// The offending value.
        value: u64,
        /// Minimum allowed value (inclusive).
        min: u64,
        /// Maximum allowed value (inclusive).
        max: u64,
    },
    /// A value is not a member of the expected set.
    NotAMember,
    /// An internal invariant was violated.
    Internal(String),
}

impl fmt::Display for PrimitiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { value, min, max } => {
                write!(f, "value {value} is out of range [{min}, {max}]")
            }
            Self::NotAMember => write!(f, "value is not a member of the set"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrimitiveError {}
