use thiserror::Error;

/// Error enum for errors in oracle
#[derive(Error, Debug, PartialEq, Eq)]
pub enum OracleError {
    /// This character is not allowed as part of an email
    #[error("The character '{0}' is not allowed as part of an email.")]
    DisallowedCharacterInEmail(char),
    /// The provided ciphertext cannot be decrypted.
    #[error("The provided ciphertext cannot be decrypted.")]
    InvalidCiphertext,
    /// The plaintext could not be parsed as key-value string.
    #[error("The plaintext could not be parsed as key-value string.")]
    InvalidKeyValueString,
    /// This field is missing from the key-value string.
    #[error("The field '{0}' is missing from the key-value string.")]
    MissingField(&'static str),
    /// Failed to parse ID as a unsigned integer.
    #[error("Failed to parse ID as a unsigned integer.")]
    InvalidId,
    /// Failed to parse role as either user or admin.
    #[error("Failed to parse role as either user or admin.")]
    InvalidRole,
    /// This field does not exists in the key-value string.
    #[error("This field does not exists in the key-value string.")]
    UnexpectedField,
}
