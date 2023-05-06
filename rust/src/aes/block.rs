use std::convert::{From, TryFrom};
use std::ops::{Index, IndexMut};

use crate::CryptopalsError;

/// Number of bytes in 128 bits (e.g. 16 bytes)
pub const BLOCK_LENGTH: usize = 16;

/// A block of 16 bytes used in AES encryption
#[derive(Default)]
pub struct Block([u8; BLOCK_LENGTH]);

impl TryFrom<&[u8]> for Block {
    type Error = CryptopalsError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        if slice.len() != BLOCK_LENGTH {
            return Err(CryptopalsError::InvalidLength);
        }

        // Initialize default block
        let mut block = Block::default();

        // Copy over each item from slice
        for (k, v) in block.0.iter_mut().zip(slice.iter()) {
            *k = *v;
        }

        // Return block
        Ok(block)
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

impl From<&Block> for Vec<u8> {
    fn from(value: &Block) -> Self {
        value.0.into()
    }
}
