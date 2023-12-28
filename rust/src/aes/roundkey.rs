use std::convert::From;

use super::{sub_byte, Block};
use crate::Bytes;

// Round constants
const ROUND_CONSTANT: [u8; 11] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

/// Iterator over the AES128 key schedule
///
/// ## Examples
/// ```
/// use cryptopals::aes::Roundkey;
///
/// // Use a 16 letter word as a key
/// let roundkey = Roundkey::try_from("counteroffensive")?;
///
/// // Initial key plus 10 rounds
/// assert_eq!(roundkey.count(), 11);
/// #
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Default)]
pub struct Roundkey {
    previous_key: Block,
    round_number: usize,
}

impl Roundkey {
    fn new(initial_key: Block) -> Roundkey {
        // Start at round 0 with the initial key
        Roundkey {
            previous_key: initial_key,
            round_number: 0,
        }
    }
}

impl From<&Bytes> for Roundkey {
    fn from(bytes: &Bytes) -> Self {
        Roundkey::new(Block::from(bytes))
    }
}

impl From<&str> for Roundkey {
    fn from(string: &str) -> Self {
        let bytes = Bytes::from(string);
        Roundkey::from(&bytes)
    }
}

impl Iterator for Roundkey {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        // Store in local variable for shorter code
        let prev = &self.previous_key;

        // Early returns
        match self.round_number {
            0 => {
                // Prepare for next round
                self.round_number += 1;

                // Return initial key
                return Some(prev.clone());
            }
            11 => {
                // No more rounds
                return None;
            }
            _ => {
                // Nothing to do
            }
        }

        // Start with a blank slate
        let mut next = Block::default();

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

        // Create reference before moving
        let roundkey = next.clone();

        // Prepare for next round
        self.round_number += 1;
        self.previous_key = next;

        // Return
        Some(roundkey)
    }
}
