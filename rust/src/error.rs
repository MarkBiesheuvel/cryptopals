use std::error::Error;
use std::fmt;

/// Error enum of this crate
#[derive(Debug, PartialEq, Eq)]
pub enum CryptopalsError {
    /// The input does not have a valid lenth
    InvalidLength,
    /// The input is not valid hexadecimal
    InvalidHexadecimal,
    /// The input is not valid base64
    InvalidBase64,
    /// The inputs are of unequal length
    UnequalLength,
    /// The input does not have enough blocks to perform operation
    NotEnoughBlocks,
    /// Unable to find likely candidate
    UnableToFindLikelyCandidate,
    /// Unable to detect block size
    UnableToDetectBlockSize,
    /// Index out of bounds
    IndexOutOfBounds,
    /// The bytes cannot be padded since they already exceed the desired length
    ExceedsDesiredLength,
}

impl fmt::Display for CryptopalsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "The input does not have a valid length"),
            Self::InvalidHexadecimal => write!(f, "The input is not valid hexadecimal"),
            Self::InvalidBase64 => write!(f, "The input is not valid base64"),
            Self::UnequalLength => write!(f, "The inputs are of unequal length"),
            Self::NotEnoughBlocks => write!(f, "The input does not have enough blocks to perform operation"),
            Self::UnableToFindLikelyCandidate => write!(f, "Unable to find likely candidate"),
            Self::UnableToDetectBlockSize => write!(f, "Unable to detect block size"),
            Self::IndexOutOfBounds => write!(f, "Index out of bounds"),
            Self::ExceedsDesiredLength => {
                write!(f, "The bytes cannot be padded since they already exceed the desired length")
            }
        }
    }
}

impl Error for CryptopalsError {}
