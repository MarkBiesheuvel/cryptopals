use std::convert::From;
use std::fmt;
use std::vec::Vec;

use crate::{ByteIterable, Hexadecimal, SliceIterator};

/// Collection of bytes
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Bytes(Vec<u8>);

impl ByteIterable for Bytes {
    /// Iterate over references to each byte
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::{ByteIterable, Bytes};
    /// #
    /// let value = Bytes::from([102, 111, 111]);
    /// let mut iter = value.iter();
    ///
    /// assert_eq!(iter.next(), Some(&102));
    /// assert_eq!(iter.next(), Some(&111));
    /// assert_eq!(iter.next(), Some(&111));
    /// assert_eq!(iter.next(), None);
    /// ```
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a u8> + 'a> {
        Box::new(self.0.iter())
    }

    /// Number of bytes stored
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::{ByteIterable, Bytes};
    /// #
    /// let value = Bytes::from("cryptopals");
    ///
    /// assert_eq!(value.length(), 10);
    /// ```
    fn length(&self) -> usize {
        self.0.len()
    }
}

impl Bytes {
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
    /// assert!(value.range(3, 7) == Some(&[112, 116, 111, 112]));
    /// ```
    pub fn range(&self, start_index: usize, end_index: usize) -> Option<&[u8]> {
        // Get a slice and convert it to Bytes struct
        self.0.get(start_index..end_index)
    }

    /// Return an iterator of blocks of this Bytes struct
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::from("cryptopals");
    /// let mut iter = value.slices(3);
    ///
    /// assert!(iter.next() == Some(&[99, 114, 121]));
    /// assert!(iter.next() == Some(&[112, 116, 111]));
    /// assert!(iter.next() == Some(&[112, 97, 108]));
    /// assert!(iter.next() == Some(&[115]));
    /// assert!(iter.next() == None);
    /// ```
    pub fn slices(&self, slice_length: usize) -> SliceIterator {
        SliceIterator::new(self, slice_length)
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
            .zip(other.0.iter().cycle()) // HACK
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect();

        Bytes(bytes)
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

        // Instead of an Result<>, let's return the XOR using the shortest input
        let output = value_1.fixed_xor(&value_2);
        let expected = Bytes::from([46, 10, 3]);

        assert_eq!(output, expected);
    }
}
