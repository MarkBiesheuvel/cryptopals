use super::{AdversaryError, DEFAULT_BYTE};
use crate::{byte::*, oracle::Oracle};
use error_stack::{Result, ResultExt};

pub fn get_ciphertext_length<O: Oracle>(oracle: &O, plaintext_length: usize) -> Result<usize, AdversaryError> {
    // Build a plaintext of desired length
    let plaintext = ByteSlice::with_repeated_byte_and_length(plaintext_length, DEFAULT_BYTE);

    // Try to encrypt it using the oracle
    let ciphertext = oracle
        .encrypt(plaintext)
        .change_context(AdversaryError::InvalidInputOracle)?;

    // Return the ciphertext length
    Ok(ciphertext.length())
}
