use super::{get_duplicated_block_index, AdversaryError};
use crate::{
    aes::{BlockMode, BLOCK_LENGTH},
    oracle::Oracle,
};
use error_stack::Result;

/// Detect whether an oracle is encrypting with ECB or CBC block cipher mode.
pub fn detect_aes_block_mode<O: Oracle>(oracle: &O) -> Result<BlockMode, AdversaryError> {
    // Purposefully chosen string for detecting AES ECB block mode.
    // The string contains an arbitrary character 48 times in a row.
    // After encrypting this plaintext with AES ECB mode, the cipher should have at
    // least two duplicated blocks.
    let mode = match get_duplicated_block_index(oracle, 3 * BLOCK_LENGTH)? {
        Some(_index) => BlockMode::Ecb,
        None => BlockMode::Cbc,
    };

    Ok(mode)
}
