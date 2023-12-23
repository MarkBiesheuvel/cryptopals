use std::iter::Iterator;

use super::Bytes;

/// Collection of equal sized blocks of bytes
#[derive(Debug)]
pub struct BlockIterator<'a> {
    bytes: &'a Bytes,
    block_size: usize,
    block_number: usize,
}

impl<'a> BlockIterator<'a> {
    /// Constructor
    ///
    /// Only allow this to be created directly from the Bytes struct
    pub(super) fn new(bytes: &'a Bytes, block_size: usize) -> BlockIterator<'a> {
        BlockIterator {
            bytes,
            block_size,
            block_number: 0,
        }
    }

    // TODO: implement constructors with padding

    /// Return block size of BlockIterator
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Return  Bytes within BlockIterator
    pub fn bytes(&self) -> &Bytes {
        self.bytes
    }
}

impl<'a> Iterator for BlockIterator<'a> {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        // Get length
        let length = self.bytes.length();

        // Calculate start and end index
        let start_index = self.block_number * self.block_size;
        let mut end_index = (self.block_number + 1) * self.block_size;

        // Early return if start index exceeds length
        if start_index >= length {
            return None;
        }

        // Adjust end index if it exceeds length
        if end_index > length {
            end_index = length;
        }

        // Increment for next iteration
        self.block_number += 1;

        self.bytes.range(start_index, end_index)
    }
}
