use std::convert::TryFrom;
use std::ops::BitXor;
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
    pub fn sub_bytes(&self) -> Block {
        // Initialize default block
        let mut result = Block::default();

        // Sub each byte
        for i in 0..BLOCK_LENGTH {
            result[i] = sub_byte(self.0[i]);
        }

        // Return new Block
        result
    }
}

impl BitXor for Block {
    type Output = Self;

    fn bitxor(self, other: Self) -> Self::Output {
        // Initialize default block
        let mut result = Block::default();

        // XOR each byte
        for i in 0..BLOCK_LENGTH {
            result[i] = self.0[i] ^ other.0[i];
        }

        // Return new Block
        result
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
