//! Unified error type for miden-zk-primitives.

use core::fmt;

/// Errors that can occur when constructing or verifying ZK primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrimitiveError {
    /// The input value falls outside the allowed range.
    OutOfRange {
        value: u64,
        min: u64,
        max: u64,
    },
    /// The element is not a member of the provided set.
    NotAMember,
    /// A generic internal error with a human-readable message.
    Internal(&'static str),
}

impl fmt::Display for PrimitiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { value, min, max } => {
                write!(f, "value {value} is outside range [{min}, {max}]")
            }
            Self::NotAMember => write!(f, "element is not a member of the set"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrimitiveError {}
