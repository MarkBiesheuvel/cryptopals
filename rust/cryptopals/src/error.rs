use thiserror::Error;

/// Error enum for general cryptographic errors
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CryptopalsError {
    /// The input does not have a valid length
    #[error("The input does not have a valid length")]
    InvalidLength,
    /// The input is not valid hexadecimal
    #[error("The input is not valid hexadecimal")]
    InvalidHexadecimal,
    /// The input is not valid base64
    #[error("The input is not valid base64")]
    InvalidBase64,
    /// The inputs are of unequal length
    #[error("The inputs are of unequal length")]
    UnequalLength,
    /// The input does not have valid padding
    #[error("The input does not have valid padding")]
    InvalidPadding,
}
