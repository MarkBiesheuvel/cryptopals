use thiserror::Error;

/// Error enum for errors in oracle
#[derive(Error, Debug, PartialEq, Eq)]
pub enum OracleError {
    /// This character is not allowed as part of an email
    #[error("The character '{0}' is not allowed as part of an email.")]
    DisallowedCharacterInEmail(char),
}
