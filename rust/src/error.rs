use std::error::Error;
use std::fmt;

/// Error enum of this crate
#[derive(Debug, PartialEq, Eq)]
pub enum CryptopalsError {
    /// The input is not valid hexadecimal
    InvalidHexadecimal,
    /// The input is not valid base64
    InvalidBase64,
    /// The inputs are of unequal length
    UnequalLength,
}

impl fmt::Display for CryptopalsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHexadecimal => write!(f, "The input is not valid hexadecimal"),
            Self::InvalidBase64 => write!(f, "The input is not valid base64"),
            Self::UnequalLength => write!(f, "The inputs are of unequal length"),
        }
    }
}

impl Error for CryptopalsError {}
