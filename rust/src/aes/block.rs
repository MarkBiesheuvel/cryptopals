use std::convert::From;
use std::ops::BitXorAssign;
use std::ops::{Index, IndexMut};

use super::sub_byte;
use crate::{Bytes, CryptopalsError};

/// Number of bytes in 128 bits (e.g. 16 bytes)
pub const BLOCK_LENGTH: usize = 16;

const LOWEST_BIT: u8 = 0b00000001;
const HIGHEST_BIT: u8 = 0b10000000;

/// Galois Field (256) Multiplication of two Bytes
fn g_mul(mut lhs: u8, mut rhs: u8) -> u8 {
    let mut result = 0;

    // Instead of always looping 8 times for 8 bits, the loop can exit once rhs is 0
    while rhs != 0 {
        let lowest_bit_set = (rhs & LOWEST_BIT) == LOWEST_BIT;
        let highest_bit_set = (lhs & HIGHEST_BIT) == HIGHEST_BIT;

        // If the lowest bit of rhs is set, XOR the result with the lhs
        if lowest_bit_set {
            result ^= lhs;
        }

        // Left bitshift lhs
        lhs <<= 1;

        // If the highest bit of lhs was set before shifting, XOR lhs with constant
        if highest_bit_set {
            lhs ^= 0x1B;
        }

        // Right bitshift rhs
        rhs >>= 1;
    }

    result
}

/// A block of 16 bytes used in AES encryption
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Block([u8; BLOCK_LENGTH]);

impl Block {
    /// Short-hand function for creating Block struct from hexadecimal encoded
    /// string
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::aes;
    /// # use std::ops::Index;
    /// #
    /// let block = aes::Block::try_from_hexadecimal("5468617473206D79204B756E67204675")?;
    ///
    /// assert_eq!(block.index(4), &115);
    /// #
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn try_from_hexadecimal<S: Into<String>>(value: S) -> Result<Block, CryptopalsError> {
        let bytes = Bytes::try_from_hexadecimal(value)?;
        let block = Block::from(&bytes);
        Ok(block)
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
        // Create a clone to store original values
        let clone = self.clone();

        // First column
        self[0] = g_mul(clone[0], 2) ^ g_mul(clone[1], 3) ^ g_mul(clone[2], 1) ^ g_mul(clone[3], 1);
        self[1] = g_mul(clone[0], 1) ^ g_mul(clone[1], 2) ^ g_mul(clone[2], 3) ^ g_mul(clone[3], 1);
        self[2] = g_mul(clone[0], 1) ^ g_mul(clone[1], 1) ^ g_mul(clone[2], 2) ^ g_mul(clone[3], 3);
        self[3] = g_mul(clone[0], 3) ^ g_mul(clone[1], 1) ^ g_mul(clone[2], 1) ^ g_mul(clone[3], 2);

        // Second column
        self[4] = g_mul(clone[4], 2) ^ g_mul(clone[5], 3) ^ g_mul(clone[6], 1) ^ g_mul(clone[7], 1);
        self[5] = g_mul(clone[4], 1) ^ g_mul(clone[5], 2) ^ g_mul(clone[6], 3) ^ g_mul(clone[7], 1);
        self[6] = g_mul(clone[4], 1) ^ g_mul(clone[5], 1) ^ g_mul(clone[6], 2) ^ g_mul(clone[7], 3);
        self[7] = g_mul(clone[4], 3) ^ g_mul(clone[5], 1) ^ g_mul(clone[6], 1) ^ g_mul(clone[7], 2);

        // Third column
        self[8] = g_mul(clone[8], 2) ^ g_mul(clone[9], 3) ^ g_mul(clone[10], 1) ^ g_mul(clone[11], 1);
        self[9] = g_mul(clone[8], 1) ^ g_mul(clone[9], 2) ^ g_mul(clone[10], 3) ^ g_mul(clone[11], 1);
        self[10] = g_mul(clone[8], 1) ^ g_mul(clone[9], 1) ^ g_mul(clone[10], 2) ^ g_mul(clone[11], 3);
        self[11] = g_mul(clone[8], 3) ^ g_mul(clone[9], 1) ^ g_mul(clone[10], 1) ^ g_mul(clone[11], 2);

        // Fourth column
        self[12] = g_mul(clone[12], 2) ^ g_mul(clone[13], 3) ^ g_mul(clone[14], 1) ^ g_mul(clone[15], 1);
        self[13] = g_mul(clone[12], 1) ^ g_mul(clone[13], 2) ^ g_mul(clone[14], 3) ^ g_mul(clone[15], 1);
        self[14] = g_mul(clone[12], 1) ^ g_mul(clone[13], 1) ^ g_mul(clone[14], 2) ^ g_mul(clone[15], 3);
        self[15] = g_mul(clone[12], 3) ^ g_mul(clone[13], 1) ^ g_mul(clone[14], 1) ^ g_mul(clone[15], 2);
    }

    /// Encrypt a single block
    ///
    ///
    /// Roundkeys need to already be calculated to avoid rerunning the Roundkey
    /// iterator for each block TODO: change the type of roundkeys
    pub fn encrypt(&mut self, roundkeys: &[Block]) {
        for (round_number, round_key) in roundkeys.iter().enumerate() {
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

impl From<Block> for Vec<u8> {
    fn from(value: Block) -> Self {
        Self::from(value.0)
    }
}

impl From<&Bytes> for Block {
    fn from(bytes: &Bytes) -> Self {
        // ALERT: cloning
        let mut bytes: Bytes = bytes.clone();

        // TODO: refactor padding function, so we do not need to clone first
        if bytes.length() < BLOCK_LENGTH {
            bytes.pad(BLOCK_LENGTH);
        }

        // Initialize default block
        let mut block = Block::default();

        // Copy over each item from slice
        for (k, v) in block.0.iter_mut().zip(bytes.iter()) {
            *k = *v;
        }

        // Return block
        block
    }
}

impl From<&str> for Block {
    fn from(string: &str) -> Self {
        let bytes = Bytes::from(string);
        Block::from(&bytes)
    }
}
