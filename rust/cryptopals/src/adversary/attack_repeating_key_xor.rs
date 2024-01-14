use error_stack::Result;

use super::{attack_single_byte_xor, detect_block_size_repeating_key, AdversaryError};
use crate::Bytes;

/// Adversary which takes a ciphertext which has been encrypted using a single
/// byte XOR and tries to reverse it
pub fn attack_repeating_key_xor(ciphertext: &Bytes) -> Result<Bytes, AdversaryError> {
    // Get length
    let length = ciphertext.length();

    // Detect block size (if possible)
    let block_size = detect_block_size_repeating_key(ciphertext)?;

    // Split cipher up into chunks where each chunk `N` contains the `N`th byte of
    // every block
    let chunks = (0..block_size)
        .map(|chunk_number| {
            // Get all bytes for a chunk
            let bytes = (chunk_number..length)
                .step_by(block_size)
                // Get each byte at position `i` where `i % block_size == chunk_number`
                .map(|i| {
                    // Verify the logic
                    assert_eq!(i % block_size, chunk_number);

                    // Get the number at specified index
                    ciphertext.get(i).unwrap()
                })
                .collect::<Vec<_>>();

            // Create new Bytes struct
            Ok(Bytes::from(bytes))
        })
        // Propagate Result::Err if any chunks could not be constructed
        .collect::<Result<Vec<_>, _>>()?;

    let chunks = chunks
        .into_iter()
        // Attack each chunk as a single byte XOR cipher
        .map(|chunk| attack_single_byte_xor(&chunk))
        // Propagate Result::Err if any chunks had an unsuccessful attack
        .collect::<Result<Vec<_>, _>>()?;

    // Reconstruct the plaintext by placing all bytes back into the original order
    let bytes = (0..length)
        .map(|i| {
            // Modulo/remainder
            let chunk_number = i % block_size;

            // Integer division
            let offset = i / block_size;

            // Retrieve byte using the inverse logic
            let byte = chunks.get(chunk_number).unwrap().get(offset).unwrap();

            byte
        })
        .collect::<Vec<_>>();

    // Create new Bytes struct
    Ok(Bytes::from(bytes))
}
