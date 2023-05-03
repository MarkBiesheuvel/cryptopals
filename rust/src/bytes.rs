use std::convert::From;
use std::fmt;
use std::slice::Iter;
use std::vec::Vec;

use crate::{BlockIterator, CryptopalsError, Hexadecimal};

/// Collection of bytes
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Iterate over references to each byte
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::from([102, 111, 111]);
    /// let mut iter = value.iter();
    ///
    /// assert_eq!(iter.next(), Some(&102));
    /// assert_eq!(iter.next(), Some(&111));
    /// assert_eq!(iter.next(), Some(&111));
    /// assert_eq!(iter.next(), None);
    /// ```
    pub fn iter(&self) -> Iter<u8> {
        self.0.iter()
    }

    /// Number of bytes stored
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::from("cryptopals");
    ///
    /// assert_eq!(value.length(), 10);
    /// ```
    pub fn length(&self) -> usize {
        self.0.len()
    }

    /// Return a single byte at an index
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::from("cryptopals");
    ///
    /// assert_eq!(value.get(4), Some(116));
    /// ```
    pub fn get(&self, index: usize) -> Option<u8> {
        self.0.get(index).copied()
    }

    /// Return a range within Bytes as a new Bytes
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::from("cryptopals");
    ///
    /// assert_eq!(value.range(3, 7), Some(Bytes::from([112, 116, 111, 112])));
    /// ```
    pub fn range(&self, start_index: usize, end_index: usize) -> Option<Bytes> {
        // Get a slice and convert it to Bytes struct
        self.0.get(start_index..end_index).map(Bytes::from)
    }

    /// Return an iterator of blocks of this Bytes struct
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::from("cryptopals");
    /// let mut iter = value.block_iterator(3);
    ///
    /// assert_eq!(iter.next(), Some(Bytes::from([99, 114, 121])));
    /// assert_eq!(iter.next(), Some(Bytes::from([112, 116, 111])));
    /// assert_eq!(iter.next(), Some(Bytes::from([112, 97, 108])));
    /// assert_eq!(iter.next(), Some(Bytes::from([115])));
    /// assert_eq!(iter.next(), None);
    /// ```
    pub fn block_iterator(&self, block_size: usize) -> BlockIterator {
        BlockIterator::new(self, block_size)
    }

    /// XOR two equally length Bytes with each other
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let plaintext = Bytes::from("cryptopals");
    /// let key = Bytes::from([12, 34, 56, 78, 90, 123, 45, 67, 89, 10]);
    /// let ciphertext = Bytes::from([111, 80, 65, 62, 46, 20, 93, 34, 53, 121]);
    ///
    /// assert_eq!(plaintext.fixed_xor(&key).unwrap(), ciphertext);
    /// ```
    pub fn fixed_xor(&self, other: &Bytes) -> Result<Bytes, CryptopalsError> {
        if self.length() != other.length() {
            return Err(CryptopalsError::UnequalLength);
        }

        let bytes = (self.iter())
            .zip(other.iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect();

        Ok(Bytes(bytes))
    }

    /// XOR all the bytes with a single other byte
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let key = 42;
    /// let plaintext = Bytes::from("cryptopals");
    /// let ciphertext = Bytes::from([73, 88, 83, 90, 94, 69, 90, 75, 70, 89]);
    ///
    /// assert_eq!(plaintext.single_byte_xor(key), ciphertext);
    /// ```
    pub fn single_byte_xor(&self, rhs: u8) -> Bytes {
        let bytes = self.iter().map(|lhs| lhs ^ rhs).collect();

        Bytes(bytes)
    }

    /// XOR all bytes with a repeated key
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let key = Bytes::from([123, 45, 67]);
    /// let plaintext = Bytes::from("cryptopals");
    /// let ciphertext = Bytes::from([24, 95, 58, 11, 89, 44, 11, 76, 47, 8]);
    ///
    /// assert_eq!(plaintext.repeated_key_xor(&key), ciphertext);
    /// ```
    pub fn repeated_key_xor(&self, other: &Bytes) -> Bytes {
        let bytes = (self.iter())
            .zip(other.iter().cycle())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect();

        Bytes(bytes)
    }

    /// Hamming distance between two Bytes structs
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let text_1 = Bytes::from("this is a test");
    /// let text_2 = Bytes::from("wokka wokka!!!");

    ///
    /// assert_eq!(text_1.hamming_distance(&text_2).unwrap(), 37);
    /// ```
    pub fn hamming_distance(&self, other: &Bytes) -> Result<u32, CryptopalsError> {
        let difference = self.fixed_xor(other)?;

        // Iterate over each byte
        let distance = difference
            .iter()
            .map(|byte| {
                // Iterate over each bit
                let number_of_bites: u8 = (0..8).map(|i: u8| (byte >> i) & 1).sum();

                // For an individual byte the number of bits different is at most 8,
                // but when summing up a long array, the total might exceed the u8 primitive
                number_of_bites as u32
            })
            .sum();

        Ok(distance)
    }
}

impl<V> From<V> for Bytes
where
    V: Into<Vec<u8>>,
{
    /// Construct a Bytes struct from anything that can be turned into a
    /// `Vec<u8>`, like for example a &str
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value_1 = Bytes::from("cryptopals");
    /// let value_2 = Bytes::from([99, 114, 121, 112, 116, 111, 112, 97, 108, 115]);
    ///
    /// assert_eq!(value_1, value_2);
    /// ```
    fn from(value: V) -> Self {
        Bytes(value.into())
    }
}

impl fmt::Debug for Bytes {
    /// Custom debug function which displays Bytes as a human readable string
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::from("cryptopals");
    ///
    /// dbg!(value);
    /// ```
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Open
        writeln!(f, "Bytes {{")?;

        // If it is possible to express as a string, add it as a "field"
        if let Ok(value) = String::from_utf8(self.0.clone()) {
            writeln!(f, "    string_repr: {:?},", value)?;
        };

        // Include hexadecimal representation
        writeln!(f, "    hexadecimal: {:?},", Hexadecimal::from(self))?;

        // Single line list of raw bytes
        // NOTE: fmt::DebugStruct will print each number in vector on a new lines, hence
        // a custom implementation
        writeln!(f, "    bytes: {:?},", self.0)?;

        // Calculated length
        writeln!(f, "    length: {:?},", self.0.len())?;

        // Close
        writeln!(f, "}}")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unequal_length_fixed_xor() {
        let value_1 = Bytes::from("Hello, World");
        let value_2 = Bytes::from("foo");

        let error = value_1.fixed_xor(&value_2).unwrap_err();
        let expected = CryptopalsError::UnequalLength;

        assert_eq!(error, expected);
    }
}
