use super::{get_ciphertext_length, get_duplicated_block_index, AdversaryError};
use crate::{aes::BLOCK_LENGTH, oracle::Oracle};
use error_stack::{ensure, Result};

/// Characteristics of an Oracle using AES ECB block mode
#[derive(Debug)]
pub struct AesEcbProperties {
    /// The number of bytes that are prepended to the plaintext before encrypting
    pub prefix_length: usize,
    /// The number of bytes that are appended to the plaintext before encrypting
    pub postfix_length: usize,
    /// The byte offset in the plaintext thats starts in a new block
    pub alignment_offset: usize,
}

/// Detect various properties of an oracle which encrypts using AES
pub fn detect_aes_properties<O: Oracle>(oracle: &O) -> Result<AesEcbProperties, AdversaryError> {
    // The properties we want to detect
    let mut prefix_length = None;
    let mut postfix_length = None;
    let mut alignment_offset = None;

    // Try plaintext input of different lengths to find the first plaintext which causes duplicated blocks
    for plaintext_length in 2 * BLOCK_LENGTH..3 * BLOCK_LENGTH {
        if let Some(duplicated_block_index) = get_duplicated_block_index(oracle, plaintext_length)? {
            // TODO: write comment
            let offset = plaintext_length - 2 * BLOCK_LENGTH;
            alignment_offset = Some(offset);

            // The first duplicated block is guaranteed to include our plaintext input.
            // Subtract the alignment offset to find the precise start point of our plaintext, and thus the length of the prefix.
            prefix_length = Some(duplicated_block_index * BLOCK_LENGTH - offset);

            // We found what we were looking for, no need to continue
            break;
        }
    }

    // If we don't see any duplicated blocks when trying all lengths from 32 to 47, then something is wrong with the oracle
    let prefix_length = prefix_length.ok_or(AdversaryError::OracleDoesNotUseEcb)?;
    let alignment_offset = alignment_offset.ok_or(AdversaryError::OracleDoesNotUseEcb)?;

    // Keeping track of the length of different ciphertexts and initialize first round
    let base_ciphertext_length = get_ciphertext_length(oracle, 0)?;

    // Try plaintext input of different lengths to find the first plaintext which increases the ciphertext by one block
    for plaintext_length in 1..=BLOCK_LENGTH {
        // Update length data
        let current_ciphertext_length = get_ciphertext_length(oracle, plaintext_length)?;

        // If the length changed since last time, exit the loop
        if base_ciphertext_length < current_ciphertext_length {
            // The block length is equal to the difference in ciphertext length
            // Since we only added one character, the padding extended the length by one block
            let block_length = current_ciphertext_length - base_ciphertext_length;
            ensure!(block_length == BLOCK_LENGTH, AdversaryError::UnexpectedBlockLength(block_length));

            // Calculate the number of additional bytes that were added to the plaintext.
            // The current plaintext length plus additional bytes fit exactly in the block length and needed another block of padding.
            // Use the previous ciphertext length to determine how many blocks that was.
            let additional_bytes_length = base_ciphertext_length - plaintext_length;

            // The additional bytes are either prefixed or postfixed, so can calculate one from the other
            postfix_length = Some(additional_bytes_length - prefix_length);

            // We found what we were looking for, no need to continue
            break;
        }
    }

    // If we don't see a change in ciphertext length when trying all lengths from 0 to 16, then something is wrong with the oracle
    let postfix_length = postfix_length.ok_or(AdversaryError::OracleAlwaysReturnsSameCiphertextLength)?;

    Ok(AesEcbProperties {
        prefix_length,
        postfix_length,
        alignment_offset,
    })
}
