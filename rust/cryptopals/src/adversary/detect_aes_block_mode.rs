use super::{AdversaryError, DEFAULT_BYTE};
use crate::{
    aes::{BlockMode, BLOCK_LENGTH},
    byte::*,
    oracle::Oracle,
};
use error_stack::{Result, ResultExt};
use itertools::Itertools;

/// Detect whether an oracle is encrypting with ECB or CBC block cipher mode.
pub fn detect_aes_block_mode<O: Oracle>(oracle: &O) -> Result<BlockMode, AdversaryError> {
    // Purposefully chosen string for detecting AES ECB block mode.
    // The string contains an arbitrary character 48 times in a row.
    // After encrypting this plaintext with AES ECB mode, the cipher should have at
    // least two repeated blocks of 16 bytes
    let plaintext = ByteSlice::with_repeated_byte_and_length(3 * BLOCK_LENGTH, DEFAULT_BYTE);

    // Let the oracle encrypt our plaintext
    let ciphertext = oracle
        .encrypt(plaintext)
        .change_context(AdversaryError::InvalidInputOracle)?;

    // Check whether the ciphertext contains any consecutive blocks that are identical.
    let contains_any_identical_blocks = ciphertext
        .blocks::<BLOCK_LENGTH>()
        .change_context(AdversaryError::UnexpectedCiphertextLength)?
        .tuple_windows()
        .any(|(block_1, block_2)| block_1 == block_2);

    let mode = if contains_any_identical_blocks {
        BlockMode::Ecb
    } else {
        BlockMode::Cbc
    };

    Ok(mode)
}
