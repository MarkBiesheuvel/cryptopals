use std::convert::TryFrom;
use std::ops::BitXorAssign;
use std::ops::{Index, IndexMut};

use super::sub_byte;
use crate::{Bytes, CryptopalsError};

/// Number of bytes in 128 bits (e.g. 16 bytes)
pub const BLOCK_LENGTH: usize = 16;

/// A block of 16 bytes used in AES encryption
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Block([u8; BLOCK_LENGTH]);

impl Block {
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
}

impl BitXorAssign for Block {
    fn bitxor_assign(&mut self, other: Self) {
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

impl TryFrom<&str> for Block {
    type Error = CryptopalsError;

    fn try_from(slice: &str) -> Result<Self, Self::Error> {
        if slice.len() != BLOCK_LENGTH {
            return Err(CryptopalsError::InvalidLength);
        }

        // Initialize default block
        let mut block = Block::default();

        // Copy over each item from slice
        for (k, v) in block.0.iter_mut().zip(slice.as_bytes().iter()) {
            *k = *v;
        }

        // Return block
        Ok(block)
    }
}

impl TryFrom<&Bytes> for Block {
    type Error = CryptopalsError;

    fn try_from(bytes: &Bytes) -> Result<Self, Self::Error> {
        if bytes.length() != BLOCK_LENGTH {
            return Err(CryptopalsError::InvalidLength);
        }

        // Initialize default block
        let mut block = Block::default();

        // Copy over each item from slice
        for (k, v) in block.0.iter_mut().zip(bytes.iter()) {
            *k = *v;
        }

        // Return block
        Ok(block)
    }
}
