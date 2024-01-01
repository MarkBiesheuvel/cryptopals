use itertools::Itertools;

use crate::{aes, oracle, Bytes};

/// Detect whether an oracle is encrypting with ECB or CBC block cipher mode.
pub fn detect_aes_block_mode(oracle: &oracle::RandomBlockMode) -> aes::BlockMode {
    // Purposefully choosen string for detecting AES ECB block mode.
    // The string contains an arbitrary character 64 times in a row.
    // After encrypting this plaintext with AES ECB mode, the cipher should have at
    // least two repeated blocks of 16 bytes
    let plaintext: Bytes = Bytes::with_repeated_character(64, 'U');

    // Let the oracle encrypt our plaintext
    let ciphertext = oracle.encrypt(plaintext);

    // Check whether the ciphertext contains any consecutive blocks that are
    // identical.
    let contains_any_identical_blocks = ciphertext
        .blocks(aes::BLOCK_LENGTH)
        .tuple_windows()
        .any(|(block_1, block_2)| block_1 == block_2);

    if contains_any_identical_blocks {
        aes::BlockMode::Ecb
    } else {
        aes::BlockMode::Cbc
    }
}
