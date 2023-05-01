use itertools::Itertools;

use crate::{BlockIterator, CryptopalsError};

// Number of blocks to sample and compare to each other to find the most likely
// key length Higher number will be more accurate, but break on shorter
// ciphertexts
const NUMBER_OF_BLOCKS: usize = 6;

// C(n, r) = n! / [(n−r)! r!]
// C(6, 2) = 6! / [(6-2)! 2!] = 6 * 5 / 2 = 15
const NUMBER_OF_COMBINATIONS: f32 = 15.0;

/// Not an adversary by itself, but used by both
/// `attack_force_repeating_key_xor` and `detect_aes_ecb_cipher`
pub fn average_hamming_distance(iterator: BlockIterator) -> Result<f32, crate::CryptopalsError> {
    // Make sure that the iterator will have enough bytes to make the combinations
    if iterator.bytes().length() / NUMBER_OF_BLOCKS < iterator.block_size() {
        return Err(CryptopalsError::NotEnoughBlocks);
    }

    // Store block size before consuming iterator
    let block_size = iterator.block_size() as f32;

    // Take the first number of blocks
    let total_distance = iterator
        .take(NUMBER_OF_BLOCKS)
        .combinations(2)
        .map(|mut combination| {
            // Get the blocks from the combination, if there are None skip over this
            // combination
            let block_1 = combination
                .pop()
                .expect("Itertools::combinations should have given 2 blocks");
            let block_2 = combination
                .pop()
                .expect("Itertools::combinations should have given 2 blocks");

            // Calculate hamming distance
            block_1
                .hamming_distance(&block_2)
                .expect("BlockIterator should have given equal length blocks")
        })
        .sum::<u32>();

    Ok(total_distance as f32 / (block_size * NUMBER_OF_COMBINATIONS))
}
