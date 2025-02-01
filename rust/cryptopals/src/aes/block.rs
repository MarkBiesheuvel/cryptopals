use std::ops::BitXorAssign;
use std::ops::{Index, IndexMut};

use super::{
    byte_operator::{g_mul, sub_byte},
    Key,
};
use crate::byte::*;

/// Number of bytes in 128 bits (e.g. 16 bytes)
pub const BLOCK_LENGTH: usize = 16;

/// A block of 16 bytes used in AES encryption
///
/// ## Examples
/// ```
/// use cryptopals::aes;
///
/// let block = aes::Block::from([42; aes::BLOCK_LENGTH]);
///
/// assert_eq!(block[11], 42);
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block(ByteArray<BLOCK_LENGTH>);

impl<B> From<B> for Block
where
    B: Into<ByteArray<16>>,
{
    fn from(value: B) -> Self {
        Block(value.into())
    }
}

impl Block {
    /// Consume self and return iterator over bytes
    pub fn into_iter(self) -> impl Iterator<Item = u8> + 'static {
        self.0.into_iter()
    }

    /// Generate a `Block` with random values.
    ///
    /// Extremely useful for creating encryption keys
    pub fn with_random_values(rng: &mut impl rand::Rng) -> Block {
        Block::from(ByteArray::with_random_values(rng))
    }

    /// Apply Rijndael S-box to all bytes of the block
    pub fn sub_bytes(&mut self) {
        // Sub each byte
        for i in 0..BLOCK_LENGTH {
            self[i] = sub_byte(self[i]);
        }
    }

    /// Cyclically shifts the bytes in each row by a certain offset
    pub fn shift_rows(&mut self) {
        // Shift first row by 0

        // Shift second row by 1
        (self[1], self[5], self[9], self[13]) = (self[5], self[9], self[13], self[1]);

        // Shift third row by 2
        (self[2], self[6], self[10], self[14]) = (self[10], self[14], self[2], self[6]);

        // Shift fourth row by 3
        (self[3], self[7], self[11], self[15]) = (self[15], self[3], self[7], self[11]);
    }

    /// Matrix multiplication with fixed matrix
    pub fn mix_columns(&mut self) {
        // Initialize new byte array
        let mut bytes = [0; BLOCK_LENGTH];

        // First column
        bytes[0] = g_mul(self[0], 2) ^ g_mul(self[1], 3) ^ g_mul(self[2], 1) ^ g_mul(self[3], 1);
        bytes[1] = g_mul(self[0], 1) ^ g_mul(self[1], 2) ^ g_mul(self[2], 3) ^ g_mul(self[3], 1);
        bytes[2] = g_mul(self[0], 1) ^ g_mul(self[1], 1) ^ g_mul(self[2], 2) ^ g_mul(self[3], 3);
        bytes[3] = g_mul(self[0], 3) ^ g_mul(self[1], 1) ^ g_mul(self[2], 1) ^ g_mul(self[3], 2);

        // Second column
        bytes[4] = g_mul(self[4], 2) ^ g_mul(self[5], 3) ^ g_mul(self[6], 1) ^ g_mul(self[7], 1);
        bytes[5] = g_mul(self[4], 1) ^ g_mul(self[5], 2) ^ g_mul(self[6], 3) ^ g_mul(self[7], 1);
        bytes[6] = g_mul(self[4], 1) ^ g_mul(self[5], 1) ^ g_mul(self[6], 2) ^ g_mul(self[7], 3);
        bytes[7] = g_mul(self[4], 3) ^ g_mul(self[5], 1) ^ g_mul(self[6], 1) ^ g_mul(self[7], 2);

        // Third column
        bytes[8] = g_mul(self[8], 2) ^ g_mul(self[9], 3) ^ g_mul(self[10], 1) ^ g_mul(self[11], 1);
        bytes[9] = g_mul(self[8], 1) ^ g_mul(self[9], 2) ^ g_mul(self[10], 3) ^ g_mul(self[11], 1);
        bytes[10] = g_mul(self[8], 1) ^ g_mul(self[9], 1) ^ g_mul(self[10], 2) ^ g_mul(self[11], 3);
        bytes[11] = g_mul(self[8], 3) ^ g_mul(self[9], 1) ^ g_mul(self[10], 1) ^ g_mul(self[11], 2);

        // Fourth column
        bytes[12] = g_mul(self[12], 2) ^ g_mul(self[13], 3) ^ g_mul(self[14], 1) ^ g_mul(self[15], 1);
        bytes[13] = g_mul(self[12], 1) ^ g_mul(self[13], 2) ^ g_mul(self[14], 3) ^ g_mul(self[15], 1);
        bytes[14] = g_mul(self[12], 1) ^ g_mul(self[13], 1) ^ g_mul(self[14], 2) ^ g_mul(self[15], 3);
        bytes[15] = g_mul(self[12], 3) ^ g_mul(self[13], 1) ^ g_mul(self[14], 1) ^ g_mul(self[15], 2);

        // Override self
        *self = Block::from(bytes)
    }

    /// Encrypt a single block
    ///
    /// Roundkeys need to already be calculated to avoid rerunning the Roundkey
    /// iterator for each block
    pub fn encrypt(&mut self, key: &Key) {
        for (round_number, round_key) in key.iter().enumerate() {
            if 0 < round_number {
                // Perform substitution bytes on every round after round 0
                self.sub_bytes();

                // Perform shift rows on every round after round 0
                self.shift_rows();

                if round_number < 10 {
                    // Perform mix columns on rounds 1 through 9
                    self.mix_columns();
                }
            }

            // Apply round key on every round
            self.bitxor_assign(round_key)
        }
    }
}

impl BitXorAssign<&Block> for Block {
    fn bitxor_assign(&mut self, other: &Block) {
        // XOR each byte
        for i in 0..BLOCK_LENGTH {
            self[i] ^= other[i];
        }
    }
}

impl Index<usize> for Block {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.0.index(index)
    }
}

impl IndexMut<usize> for Block {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.0.index_mut(index)
    }
}
