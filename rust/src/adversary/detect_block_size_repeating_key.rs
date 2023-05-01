use super::average_hamming_distance;
use crate::Bytes;

const MIN_BLOCK_SIZE: usize = 2;
const MAX_BLOCK_SIZE: usize = 40;

/// Detect block size of a repeating XOR ciphertext by looking for the block
/// size which leads to the lowest normalized hamming distance between blocks
pub fn detect_block_size_repeating_key(ciphertext: &Bytes) -> Option<usize> {
    (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE)
        .map(|block_size| {
            // Create block iterator for specific block size
            let block_iterator = ciphertext.block_iterator(block_size);

            // Calculate average hamming distance between first few blocks
            let distance = average_hamming_distance(block_iterator).unwrap();

            // Return as tuple
            (block_size, distance)
        })
        .min_by(|(_, distance_1), (_, distance_2)| {
            // Compare the distances of two bocks
            distance_1.total_cmp(distance_2)
        })
        .map(|(block_size, _)| {
            // Return the block_size (and drop the distance)
            block_size
        })
}
