use std::iter::Iterator;

use super::Bytes;

/// Collection of equal sized blocks of bytes
#[derive(Debug)]
pub struct SliceIterator<'a> {
    bytes: &'a Bytes,
    slice_length: usize,
    block_number: usize,
}

impl<'a> SliceIterator<'a> {
    /// Constructor
    ///
    /// Only allow this to be created directly from the Bytes struct
    pub(super) fn new(bytes: &'a Bytes, slice_length: usize) -> SliceIterator<'a> {
        SliceIterator {
            bytes,
            slice_length,
            block_number: 0,
        }
    }

    /// Return slice length of SliceIterator
    pub fn slice_length(&self) -> usize {
        self.slice_length
    }

    /// Return Bytes reference within SliceIterator
    pub fn bytes(&self) -> &Bytes {
        self.bytes
    }
}

impl<'a> Iterator for SliceIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // Get length
        let length = self.bytes.length();

        // Calculate start and end index
        let start_index = self.block_number * self.slice_length;
        let mut end_index = (self.block_number + 1) * self.slice_length;

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
