/// Error enum of this crate
#[derive(Debug, PartialEq, Eq)]
pub enum CryptopalsError {
    InvalidHexadecimal,
    InvalidBase64,
    UnequalLength,
}
