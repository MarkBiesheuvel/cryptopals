use super::{detect_aes_properties, AdversaryError, AesEcbProperties, DEFAULT_BYTE};
use crate::{aes::BLOCK_LENGTH, byte::*, oracle::Oracle};
use error_stack::{Result, ResultExt};
use std::collections::HashMap;

// List of printable ASCII characters
const PRINTABLE_CHARACTERS: [u8; 97] = [
    9, 10, 13, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
    58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
    87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
];

fn get_nth_block_of_ciphertext<O: Oracle>(
    oracle: &O,
    plaintext: ByteSlice<'_>,
    block_length: usize,
    block_index: usize,
) -> Result<ByteSlice<'static>, AdversaryError> {
    // Try to encrypt it using the oracle
    let ciphertext = oracle
        .encrypt(plaintext)
        .change_context(AdversaryError::InvalidInputOracle)?;

    // Try to find the desired block
    let block = ciphertext
        .chunks(block_length)
        .nth(block_index)
        .ok_or(AdversaryError::UnexpectedCiphertextLength)?;

    // TODO: solve issue that block is a reference to ciphertext
    let block = ByteSlice::from_iter(block.into_iter());

    Ok(block)
}

/// Attack the the postfix of an Oracle encrypting with ECB mode
pub fn attack_ecb_fixed_postfix<O: Oracle>(oracle: &O) -> Result<ByteSlice<'static>, AdversaryError> {
    let AesEcbProperties {
        postfix_length,
        prefix_length,
        alignment_offset: _,
    } = detect_aes_properties(oracle)?;

    // Starting with no known characters
    let mut known_characters = ByteSlice::from(Vec::new());

    // Brute force each character of the fixed postfix one by one
    for byte_index in prefix_length..(prefix_length + postfix_length) {
        // Calculate the block number within the plaintext/cipher which will contain the
        // character we are looking for
        let block_index = (prefix_length + byte_index) / BLOCK_LENGTH;

        // Prefix all plaintexts with a specific number of bytes to align the
        // character we are looking for in the last position of a block in the ciphertext
        let alignment_offset = (block_index + 1) * BLOCK_LENGTH - byte_index - 1;
        let alignment_text = ByteSlice::with_repeated_byte_and_length(alignment_offset, DEFAULT_BYTE);

        // Build a map of encrypted blocks where the corresponding plaintext block was
        // our prefix + known characters + a printable byte value
        let mut block_map = PRINTABLE_CHARACTERS
            .into_iter()
            .map(|byte_value| {
                // Create plaintexts from the prefix, followed by all known characters, followed
                // by byte value
                let mut plaintext = &alignment_text + &known_characters;
                plaintext.push(byte_value);

                // Store the block of the ciphertext containing the different bytes values in
                // the last position
                let block = get_nth_block_of_ciphertext(oracle, plaintext, BLOCK_LENGTH, block_index)?;

                Ok((block, byte_value))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        // Encrypt only the prefix and lookup the block in the dictionary
        //
        // Visualization:
        // - block length is 4
        // - prefix is p
        // - fixed postfix has 5 characters (2 are known `k` and 3 unknown `u`)
        // - printable byte value is B
        //
        // pppp [pkkB] kkuu u
        // pppp [pkku] uu
        let block = get_nth_block_of_ciphertext(oracle, alignment_text, BLOCK_LENGTH, block_index)?;

        // Add the discovered character to the list of known characters so it can be
        // used in the next step
        let byte_value = block_map.remove(&block).unwrap();
        known_characters.push(byte_value);
    }

    // All characters are known, this must be the fixed postfix
    Ok(known_characters)
}
