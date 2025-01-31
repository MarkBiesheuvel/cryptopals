use error_stack::{Result, ResultExt};
use itertools::Itertools;

use super::AdversaryError;
use crate::{aes, byte::*, oracle::Oracle};

const DEFAULT_CHARACTER: u8 = b'U';

/// Detect whether an oracle is encrypting with ECB or CBC block cipher mode.
pub fn detect_aes_block_mode<O: Oracle>(oracle: &O) -> Result<aes::BlockMode, AdversaryError> {
    // Purposefully chosen string for detecting AES ECB block mode.
    // The string contains an arbitrary character 64 times in a row.
    // After encrypting this plaintext with AES ECB mode, the cipher should have at
    // least two repeated blocks of 16 bytes
    let plaintext = ByteSlice::with_repeated_byte_and_length(64, DEFAULT_CHARACTER);

    // Let the oracle encrypt our plaintext
    let ciphertext = oracle
        .encrypt(plaintext)
        .change_context(AdversaryError::InvalidInputOracle)?;

    // Check whether the ciphertext contains any consecutive blocks that are
    // identical.
    let contains_any_identical_blocks = ciphertext
        .blocks::<{ aes::BLOCK_LENGTH }>()
        .tuple_windows()
        .any(|(block_1, block_2)| block_1 == block_2);

    let mode = if contains_any_identical_blocks {
        aes::BlockMode::Ecb
    } else {
        aes::BlockMode::Cbc
    };

    Ok(mode)
}
