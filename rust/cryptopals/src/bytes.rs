use std::convert::From;
use std::fmt;
use std::ops::{Add, AddAssign};
use std::vec::Vec;

use error_stack::{ensure, Result};

use crate::{Base64, CryptopalsError, Hexadecimal};

/// Collection of bytes
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Create a new `Bytes` struct of the given `length` which repeats the
    /// given `character`
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::with_repeated_character(33, 'a');
    /// let expected = Bytes::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ///
    /// assert_eq!(value, expected);
    /// ```
    pub fn with_repeated_character(length: usize, character: char) -> Bytes {
        Bytes::from_iter((0..length).map(|_| character as u8))
    }

    /// Create a new `Bytes` struct of the given `length` containing randoms
    /// values
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// # use rand::Rng;
    /// #
    /// let desired_length = 42;
    /// let mut rng = rand::thread_rng();
    /// let value = Bytes::with_random_values(42, &mut rng);
    ///
    /// assert_eq!(value.length(), desired_length);
    /// ```
    pub fn with_random_values<R: rand::Rng>(length: usize, rng: &mut R) -> Bytes {
        Bytes::from_iter((0..length).map(|_| rng.gen()))
    }

    /// Short-hand function for creating `Bytes` struct from base64 encoded
    /// string
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::try_from_base64("Y3J5cHRvcGFscw==")?;
    /// let expected = Bytes::from("cryptopals");
    ///
    /// assert_eq!(value, expected);
    /// #
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn try_from_base64<S: Into<String>>(value: S) -> Result<Bytes, CryptopalsError> {
        Bytes::try_from(Base64::from(value))
    }

    /// Short-hand function for creating `Bytes` struct from hexadecimal encoded
    /// string
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::try_from_hexadecimal("63727970746F70616C73")?;
    /// let expected = Bytes::from("cryptopals");
    ///
    /// assert_eq!(value, expected);
    /// #
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn try_from_hexadecimal<S: Into<String>>(value: S) -> Result<Bytes, CryptopalsError> {
        Bytes::try_from(Hexadecimal::from(value))
    }

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
    pub fn iter(&self) -> Box<dyn Iterator<Item = &u8> + '_> {
        Box::new(self.0.iter())
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

    /// Add additional bytes to reach desired length
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::from("cryptopals");
    /// let expected = Bytes::from([
    ///     99, 114, 121, 112, 116, 111, 112, 97, 108, 115, 6, 6, 6, 6, 6, 6,
    /// ]);
    ///
    /// assert_eq!(value.pad(16), expected);
    /// ```
    pub fn pad(&self, desired_block_lenght: usize) -> Bytes {
        let current_length = self.length();

        // Calculate the difference in length
        let difference = desired_block_lenght - (current_length % desired_block_lenght);

        // Calculate the desired length
        let desired_length = current_length + difference;

        // Copy the bytes from `self` and append the `difference`
        let bytes = (0..desired_length)
            .map(|i| match self.get(i) {
                Some(value) => value,
                None => difference as u8,
            })
            .collect::<Vec<_>>();

        Bytes(bytes)
    }

    /// Return an iterator of blocks of this Bytes struct
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value = Bytes::from("cryptopals");
    /// let mut iter = value.blocks(3);
    ///
    /// assert_eq!(iter.next(), Some(Bytes::from([99, 114, 121])));
    /// assert_eq!(iter.next(), Some(Bytes::from([112, 116, 111])));
    /// assert_eq!(iter.next(), Some(Bytes::from([112, 97, 108])));
    /// assert_eq!(iter.next(), Some(Bytes::from([115])));
    /// assert_eq!(iter.next(), None);
    /// ```
    // TODO: create two seperate functions `blocks` and `chunks` for fixed and
    // variable length arrays
    pub fn blocks(&self, block_size: usize) -> Box<dyn Iterator<Item = Bytes> + '_> {
        Box::new(self.0.chunks(block_size).map(Bytes::from))
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
    /// assert_eq!(plaintext.fixed_xor(&key)?, ciphertext);
    /// #
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn fixed_xor(&self, other: &Bytes) -> Result<Bytes, CryptopalsError> {
        ensure!(self.length() == other.length(), CryptopalsError::UnequalLength);

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
    pub fn repeated_key_xor(&self, key: &Bytes) -> Bytes {
        // Collect all references in a Vec
        let key = key.iter().collect::<Vec<_>>();

        // Cycle the Vec
        let repeated_key = key.into_iter().cycle();

        let bytes = self
            .iter()
            .zip(repeated_key)
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
    /// assert_eq!(text_1.hamming_distance(&text_2)?, 37);
    /// #
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn hamming_distance(&self, other: &Bytes) -> Result<usize, CryptopalsError> {
        let difference = self.fixed_xor(other)?;

        // Iterate over each byte
        let distance = difference
            .iter()
            .map(|byte| {
                // Iterate over each bit and sum the bits that are 1
                let number_of_bits = (0..8).map(|i: u8| (byte >> i) & 1).sum::<u8>();

                // For an individual byte the number of bits different is at most 8,
                // but when summing up a long array, the total might exceed the u8 primitive
                number_of_bits as usize
            })
            .sum();

        Ok(distance)
    }
}

impl Add<&Bytes> for Bytes {
    type Output = Bytes;

    /// Add a `&Bytes` reference to an owned `Bytes`
    fn add(mut self, rhs: &Bytes) -> Self::Output {
        // Clone the rhs and append it to self
        let mut clone = rhs.0.clone();
        self.0.append(&mut clone);

        self
    }
}

impl Add for &Bytes {
    type Output = Bytes;

    /// Add two `&Bytes` references together
    fn add(self, rhs: Self) -> Self::Output {
        // Create a new iterator which chains the lhs and rhs together and copies the
        // values
        let iter = self.iter().chain(rhs.iter()).copied();

        // Create new struct from iterator
        Bytes::from_iter(iter)
    }
}

impl AddAssign<u8> for Bytes {
    // Add a single byte to the end of a `Bytes` struct
    fn add_assign(&mut self, rhs: u8) {
        self.0.push(rhs);
    }
}

impl<V> From<V> for Bytes
where
    V: Into<Vec<u8>>,
{
    /// Construct a `Bytes` struct from anything that can be turned into a
    /// `Vec<u8>`; for example a `&str` or `[u8; N]`.
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

impl FromIterator<u8> for Bytes {
    /// Construct a `Bytes` struct from an iterator over `u8` values.
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::Bytes;
    /// #
    /// let value_1 = Bytes::from("abcdefghijklmnopqrstuvwxyz");
    /// let value_2 = Bytes::from_iter((97..).take(26));
    ///
    /// assert_eq!(value_1, value_2);
    /// ```
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = u8>,
    {
        let values = iter.into_iter().collect();
        Bytes(values)
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

        let result = value_1.fixed_xor(&value_2);

        assert!(result.is_err());
    }
}
