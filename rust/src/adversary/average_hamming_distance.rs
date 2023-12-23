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
    // Store block size before consuming iterator
    let block_size = iterator.block_size() as f32;

    // Get the first blocks and store in a Vec
    let blocks = iterator.take(NUMBER_OF_BLOCKS).collect::<Vec<_>>();

    // Create all possible combinations as a Tuple
    let combinations = (0..NUMBER_OF_BLOCKS)
        .flat_map(|i| (i..NUMBER_OF_BLOCKS).map(move |j| (i, j)))
        // Use indexes to get reference from Vec
        .map(|(index_1, index_2)| {
            let block_1 = blocks
                .get(index_1)
                .ok_or(CryptopalsError::NotEnoughBlocks)?;

            let block_2 = blocks
                .get(index_2)
                .ok_or(CryptopalsError::NotEnoughBlocks)?;

            Ok((block_1, block_2))
        })
        // Propagate Result::Err if there were not enough blocks
        .collect::<Result<Vec<_>, CryptopalsError>>()?;

    // Calculate total distance
    let total_distance = combinations
        .into_iter()
        // Calculate hamming distance for each combination
        .map(|(block_1, block_2)| block_1.hamming_distance(block_2))
        // Propagate Result::Err if any combination had unequal lengths
        .collect::<Result<Vec<_>, CryptopalsError>>()?
        // Turn back into iterator
        .into_iter()
        // Sum over all combination
        .sum::<usize>();

    Ok(total_distance as f32 / (block_size * NUMBER_OF_COMBINATIONS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bytes;

    #[test]
    fn just_enough_blocks() {
        let value = Bytes::from("Hello, World");
        let iter = value.block_iterator(2);

        let result = average_hamming_distance(iter).unwrap();

        assert_eq!(result, 43.0 / 15.0);
    }

    #[test]
    fn not_enough_blocks() {
        let value = Bytes::from("Hello, World");
        let iter = value.block_iterator(3);

        let error = average_hamming_distance(iter).unwrap_err();
        let expected = CryptopalsError::NotEnoughBlocks;

        assert_eq!(error, expected);
    }
}
