use super::average_hamming_distance;
use crate::{Bytes, CryptopalsError};

const MIN_BLOCK_SIZE: usize = 2;
const MAX_BLOCK_SIZE: usize = 40;

/// Detect block size of a repeating XOR ciphertext by looking for the block
/// size which leads to the lowest normalized hamming distance between blocks
pub fn detect_block_size_repeating_key(ciphertext: &Bytes) -> Result<usize, CryptopalsError> {
    (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE)
        .filter_map(|block_size| {
            // Create block iterator for specific block size
            let block_iterator = ciphertext.block_iterator(block_size);

            // Calculate average hamming distance between first few blocks
            match average_hamming_distance(block_iterator) {
                // Return as tuple
                Ok(distance) => Some((block_size, distance)),

                // Filter out any block size that lead to an error
                Err(_) => None,
            }
        })
        // Compare the distances of two bocks
        .min_by(|(_, distance_1), (_, distance_2)| distance_1.total_cmp(distance_2))
        // Return the block_size (and drop the distance)
        .map(|(block_size, _)| block_size)
        // Map Option<_> to Result<_, _>
        .ok_or(CryptopalsError::UnableToDetectBlockSize)
}
