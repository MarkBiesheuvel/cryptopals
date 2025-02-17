use super::{AdversaryError, DEFAULT_BYTE};
use crate::{aes::BLOCK_LENGTH, byte::*, oracle::Oracle};
use error_stack::{Result, ResultExt};

// Get the block index within the ciphertext of the first consecutive duplicated blocks.
pub fn get_duplicated_block_index<O: Oracle>(
    oracle: &O,
    plaintext_length: usize,
) -> Result<Option<usize>, AdversaryError> {
    // Construct a plaintext
    let plaintext = ByteSlice::with_repeated_byte_and_length(plaintext_length, DEFAULT_BYTE);

    // Let the oracle encrypt our plaintext
    let ciphertext = oracle
        .encrypt(plaintext)
        .change_context(AdversaryError::InvalidInputOracle)?;

    // Split up into blocks
    let blocks = ciphertext
        .blocks::<BLOCK_LENGTH>()
        .expect("ciphertext should be correct length")
        .collect::<Vec<_>>();

    // Loop through all pairs of consecutive blocks
    for index in 0..blocks.len() - 1 {
        let current_block = &blocks[index];
        let next_block = &blocks[index + 1];

        // If the blocks are equal, return early
        if current_block == next_block {
            return Ok(Some(index));
        }
    }

    // No duplicated blocks found
    Ok(None)
}
