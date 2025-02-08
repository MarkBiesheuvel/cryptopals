use super::AdversaryError;
use crate::{aes, byte::*, oracle::Oracle};
use error_stack::{ensure, Result, ResultExt};

const DEFAULT_CHARACTER: u8 = b'U';

fn ciphertext_length<O: Oracle>(oracle: &O, plaintext_length: usize) -> Result<usize, AdversaryError> {
    // Build a plaintext of desired length
    let plaintext = ByteSlice::with_repeated_byte_and_length(plaintext_length, DEFAULT_CHARACTER);

    // Try to encrypt it using the oracle
    let ciphertext = oracle
        .encrypt(plaintext)
        .change_context(AdversaryError::InvalidInputOracle)?;

    // Return the ciphertext length
    Ok(ciphertext.length())
}

/// Find the length of the postfix of an Oracle encrypting with ECB mode
pub fn find_ecb_postfix_length<O: Oracle>(oracle: &O) -> Result<usize, AdversaryError> {
    // Initialize all variables before entering the while loop
    let mut plaintext_length = 0;
    let mut current_ciphertext_length = ciphertext_length(oracle, plaintext_length)?;
    let mut previous_ciphertext_length;

    loop {
        // Recalculate the values for new plaintext length
        previous_ciphertext_length = current_ciphertext_length;
        current_ciphertext_length = ciphertext_length(oracle, plaintext_length)?;

        if previous_ciphertext_length != current_ciphertext_length {
            break;
        }

        // Increase the length of the plaintext
        plaintext_length += 1;
    }

    // The block length is equal to the difference in ciphertext length
    // Since we only added one character, the padding extended the length by one
    // block
    let block_length = current_ciphertext_length - previous_ciphertext_length;
    ensure!(block_length == aes::BLOCK_LENGTH, AdversaryError::UnexpectedBlockLength(block_length));

    // Calculate the length of the postfix string that was appended to the plaintext
    // The current plaintext length plus postfix length fit exactly in the block
    // size and therefore needed another block of padding. Use the previous
    // ciphertext length to determine how many blocks that was.
    let postfix_length = previous_ciphertext_length - plaintext_length;

    Ok(postfix_length)
}
