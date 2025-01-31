use std::convert::From;

use super::{byte_operator::sub_byte, Block, BLOCK_LENGTH};

// Round constants
const ROUND_CONSTANT: [u8; 11] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

/// Iterator over the AES128 key schedule
///
/// ## Examples
/// ```
/// # use rand::Rng;
/// # use cryptopals::aes;
/// #
/// // Generate a random key
/// let mut rng = rand::thread_rng();
/// let key = aes::Block::with_random_values(&mut rng);
///
/// // Expand round keys
/// let roundkey = aes::Roundkey::from(key);
///
/// // Initial key plus 10 rounds
/// assert_eq!(roundkey.count(), 11);
/// #
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Roundkey {
    previous_key: Option<Block>,
    round_number: usize,
}

impl Roundkey {
    fn new(initial_key: Block) -> Roundkey {
        // Start at round 0 with the initial key
        Roundkey {
            previous_key: Option::Some(initial_key),
            round_number: 0,
        }
    }
}

impl<B> From<B> for Roundkey
where
    B: Into<Block>,
{
    fn from(value: B) -> Self {
        Roundkey::new(value.into())
    }
}

impl Iterator for Roundkey {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        // Early returns
        match self.round_number {
            0 => {
                // Prepare for next round
                self.round_number += 1;

                // Return initial key
                return Some(self.previous_key.as_ref().unwrap().clone());
            }
            11 => {
                // No more rounds
                return None;
            }
            _ => {
                // Nothing to do
            }
        }

        // Taking previous key from Option and leaving None
        let prev = self.previous_key.take().unwrap();

        // Start with a blank slate
        let mut next = [0; BLOCK_LENGTH];

        // Round constant
        let constant = ROUND_CONSTANT[self.round_number];

        // W[i] = W[i-4] XOR SubWord(RotWord(W[i-1]))
        next[0] = prev[0] ^ sub_byte(prev[13]) ^ constant;
        next[1] = prev[1] ^ sub_byte(prev[14]);
        next[2] = prev[2] ^ sub_byte(prev[15]);
        next[3] = prev[3] ^ sub_byte(prev[12]);

        // W[i] = W[i-4] XOR W[i-1]
        next[4] = prev[4] ^ next[0];
        next[5] = prev[5] ^ next[1];
        next[6] = prev[6] ^ next[2];
        next[7] = prev[7] ^ next[3];

        // W[i] = W[i-4] XOR W[i-1]
        next[8] = prev[8] ^ next[4];
        next[9] = prev[9] ^ next[5];
        next[10] = prev[10] ^ next[6];
        next[11] = prev[11] ^ next[7];

        // W[i] = W[i-4] XOR W[i-1]
        next[12] = prev[12] ^ next[8];
        next[13] = prev[13] ^ next[9];
        next[14] = prev[14] ^ next[10];
        next[15] = prev[15] ^ next[11];

        let key = Block::from(next);

        // Prepare for next round
        self.round_number += 1;
        self.previous_key = Some(key.clone());

        // Return
        Some(key)
    }
}
