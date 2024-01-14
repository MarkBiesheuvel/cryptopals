use error_stack::{report, Result};

use super::{average_hamming_distance, AdversaryError};
use crate::{Bytes, ScoredBox};

const MIN_BLOCK_SIZE: usize = 2;
const MAX_BLOCK_SIZE: usize = 40;

/// Detect block size of a repeating XOR ciphertext by looking for the block
/// size which leads to the lowest normalized hamming distance between blocks
pub fn detect_block_size_repeating_key(ciphertext: &Bytes) -> Result<usize, AdversaryError> {
    (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE)
        .filter_map(|block_size| {
            // Calculate average hamming distance between first few blocks
            let distance = average_hamming_distance(ciphertext, block_size)
                // Filter out any block size that lead to an error
                .ok()?;

            Some(ScoredBox::new(distance, block_size))
        })
        // Find the block size with the lowest average hamming distance
        .min()
        // Return the block_size
        .map(ScoredBox::unbox)
        // Map Option<_> to Result<_, _>
        .ok_or(report!(AdversaryError::UnableToDetectBlockSize))
}
