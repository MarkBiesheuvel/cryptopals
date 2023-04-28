#[derive(Debug, PartialEq, Eq)]
pub enum CryptopalsError {
    InvalidHexadecimal,
    InvalidBase64,
    UnequalLength,
}
