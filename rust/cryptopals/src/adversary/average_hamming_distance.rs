use error_stack::{ensure, Result};
use itertools::Itertools;

use super::AdversaryError;
use crate::Bytes;

// The maximum number of blocks to sample and compare to each other to calculate
// the average hamming distance.
const NUMBER_OF_BLOCKS: usize = 6;

/// Not an adversary by itself, but used by both
/// `attack_repeating_key_xor` and `find_aes_ecb_ciphertext`
pub fn average_hamming_distance(bytes: &Bytes, block_size: usize) -> Result<f32, AdversaryError> {
    // Get the first N blocks and store in a Vec
    let blocks = bytes
        .blocks(block_size)
        .take(NUMBER_OF_BLOCKS)
        .collect::<Vec<_>>();

    // Create all possible combinations as a Tuple
    let combinations = blocks.into_iter().tuple_combinations().collect::<Vec<_>>();

    // Count the actual number of combinations
    let number_of_combinations = combinations.len();

    // If there is less than one block, it's not possible to calculate hamming
    // distance
    ensure!(number_of_combinations > 1, AdversaryError::UnableToCalculateAverageHammingDistance);

    // Calculate total distance
    let total_distance = combinations
        .into_iter()
        // Calculate hamming distance for each combination
        .map(|(block_1, block_2)| block_1.hamming_distance(&block_2).unwrap())
        // Sum over all combination
        .sum::<usize>();

    Ok(total_distance as f32 / (block_size as f32 * number_of_combinations as f32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bytes;

    #[test]
    fn full_amount_of_blocks() {
        let value = Bytes::from("Hello, World");

        let result = average_hamming_distance(&value, 2);

        assert_eq!(result.unwrap(), 43.0 / 15.0);
    }

    #[test]
    fn barely_enough_blocks() {
        let value = Bytes::from("Hello, World");

        // Due to a change in the implementation, the function will even work if there
        // is a lower number of blocks
        let result = average_hamming_distance(&value, 3);

        assert_eq!(result.unwrap(), 16.0 / 6.0);
    }

    #[test]
    fn not_enough_blocks() {
        let value = Bytes::from("Hello, World");

        // However, it will fail if there are 0 or 1 blocks
        let result = average_hamming_distance(&value, 16);

        assert!(result.is_err());
    }
}
