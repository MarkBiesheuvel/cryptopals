use super::{ByteArray, ByteSequence};
use crate::{aes::BLOCK_LENGTH, CryptopalsError};
use byte_encoding::encode_hexadecimal;
use error_stack::{ensure, Result};
use itermore::IterArrayChunks;
use std::{borrow::Cow, fmt, ops::Add};

/// A dynamically sized collection of bytes.
///
/// It is both possible to create a `ByteSlice` from a borrowed or an owned value.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ByteSlice<'a>(Cow<'a, [u8]>);

impl From<Vec<u8>> for ByteSlice<'static> {
    /// Create a `ByteSlice` from an owned value
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let owned_value = Vec::from([99, 114, 121, 112, 116, 111, 112, 97, 108, 115]);
    /// let value = ByteSlice::from(owned_value);
    ///
    /// assert_eq!(value.get(0), Some(&99));
    /// ```
    fn from(value: Vec<u8>) -> Self {
        ByteSlice(Cow::Owned(value))
    }
}

impl From<String> for ByteSlice<'static> {
    /// Create a `ByteSlice` from an owned value
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let user_name = "Mark";
    /// let string_value = format!("Hello, {}!", user_name);
    /// let value = ByteSlice::from(string_value);
    ///
    /// assert_eq!(value.get(8), Some(&97));
    /// ```
    fn from(value: String) -> Self {
        ByteSlice::from(value.into_bytes())
    }
}

impl<'a> From<&'a [u8]> for ByteSlice<'a> {
    /// Create a `ByteSlice` from a borrowed value
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let borrowed_value = &[99, 114, 121, 112, 116, 111, 112, 97, 108, 115][..];
    /// let value = ByteSlice::from(borrowed_value);
    ///
    /// assert_eq!(value.get(1), Some(&114));
    /// ```
    fn from(value: &'a [u8]) -> Self {
        ByteSlice(Cow::Borrowed(value))
    }
}

impl<'a> From<&'a str> for ByteSlice<'a> {
    /// Create a `ByteSlice` from a borrowed value
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let string_value = "cryptopals";
    /// let value = ByteSlice::from(string_value);
    ///
    /// assert_eq!(value.get(2), Some(&121));
    /// ```
    fn from(value: &'a str) -> Self {
        ByteSlice::from(value.as_bytes())
    }
}

impl<'a> ByteSlice<'a> {
    /// Pad additional bytes to reach desired block size.
    /// The length of the result will be a multiple of the block size.
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let mut value = ByteSlice::from("cryptopals");
    /// let block_size = 16;
    ///
    /// value.pad(block_size);
    /// let length = value.length();
    ///
    /// assert_eq!(length % block_size, 0);
    /// assert_eq!(value.get(length - 1), Some(&6));
    /// ```
    pub fn pad(&mut self, desired_block_size: usize) {
        let current_length = self.length();

        // Calculate the difference in length
        let difference = desired_block_size - (current_length % desired_block_size);

        // Calculate the desired length
        let desired_length = current_length + difference;

        // Convert to u8
        let byte = difference as u8;

        // Add characters
        for _ in current_length..desired_length {
            self.push(byte);
        }
    }

    /// Unpad bytes
    /// TODO: write example
    pub fn unpad(&mut self) -> Result<(), CryptopalsError> {
        let vec = self.0.to_mut();

        // Pop at least one byte
        let difference = vec.pop().ok_or(CryptopalsError::InvalidLength)?;

        // Validate difference
        ensure!(difference <= BLOCK_LENGTH as u8, CryptopalsError::InvalidPadding);

        // Pop remaining bytes
        for _ in 1..difference {
            // If no more bytes, the input was too short
            let byte = vec.pop().ok_or(CryptopalsError::InvalidLength)?;
            // If the byte doesn't match, the padding was invalid
            ensure!(byte == difference, CryptopalsError::InvalidPadding);
        }

        Ok(())
    }

    /// Add one single byte at the end
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let mut value = ByteSlice::from("cryptopal");
    /// assert_eq!(value.length(), 9);
    ///
    /// value.push(b's');
    /// assert_eq!(value.length(), 10);
    /// ```
    pub fn push(&mut self, value: u8) {
        self.0.to_mut().push(value);
    }

    /// XOR all bytes with a repeated key
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let key = ByteSlice::from(&[123, 45, 67][..]);
    /// let plaintext = ByteSlice::from("cryptopals");
    /// let ciphertext = ByteSlice::from(&[24, 95, 58, 11, 89, 44, 11, 76, 47, 8][..]);
    ///
    /// assert_eq!(plaintext.repeated_key_xor(&key), ciphertext);
    /// ```
    pub fn repeated_key_xor(&self, key: &Self) -> ByteSlice<'static> {
        // Collect all references in a Vec
        let key = key.iter().collect::<Vec<_>>();

        // Cycle the Vec
        let repeated_key = key.into_iter().cycle();

        let iter = self.iter().zip(repeated_key).map(|(lhs, rhs)| lhs ^ rhs);

        ByteSlice::from_iter(iter)
    }

    /// Return an iterator of chunks of this `ByteSlice`.
    ///
    /// Chunks will be of the given `chunk_size`. The last chunk might be shorter.
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let value = ByteSlice::from("cryptopals");
    /// let mut iter = value.chunks(3);
    ///
    /// assert_eq!(iter.next(), Some(ByteSlice::from("cry")));
    /// assert_eq!(iter.next(), Some(ByteSlice::from("pto")));
    /// assert_eq!(iter.next(), Some(ByteSlice::from("pal")));
    /// assert_eq!(iter.next(), Some(ByteSlice::from("s")));
    /// assert_eq!(iter.next(), None);
    /// ```
    pub fn chunks(&'a self, chunk_size: usize) -> impl Iterator<Item = ByteSlice<'a>> + 'a {
        self.0.chunks(chunk_size).map(ByteSlice::from)
    }

    /// Return an iterator of static sized blocks of this `ByteSlice`.
    /// The input will be padded first.
    pub fn blocks<const N: usize>(
        self,
    ) -> Result<impl Iterator<Item = ByteArray<N>> + 'static + use<'a, N>, CryptopalsError> {
        // The input should be divisible by the block length
        ensure!(self.length() % N == 0, CryptopalsError::InvalidLength);

        // Use the `itermore`` crate while `array_chunks` is unstable
        let iterator = self.into_iter().array_chunks().map(ByteArray::<N>::from);

        Ok(iterator)
    }
}

impl ByteSequence for ByteSlice<'_> {
    type FromIterOutput = ByteSlice<'static>;

    /// Construct a `ByteSlice` struct from an iterator over `u8` values.
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let value_1 = ByteSlice::from("abcdefghijklmnopqrstuvwxyz");
    /// let value_2 = ByteSlice::from_iter((97..).take(26));
    ///
    /// assert_eq!(value_1, value_2);
    /// ```
    fn from_iter<I>(iter: I) -> Self::FromIterOutput
    where
        I: IntoIterator<Item = u8>,
    {
        let values = iter.into_iter().collect::<Vec<_>>();
        ByteSlice::from(values)
    }

    /// Return number of bytes stored
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let value = ByteSlice::from("cryptopals");
    ///
    /// assert_eq!(value.length(), 10);
    /// ```
    fn length(&self) -> usize {
        self.0.len()
    }

    /// Return a single byte at an index
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let value = ByteSlice::from("cryptopals");
    ///
    /// assert_eq!(value.get(4), Some(&116));
    /// ```
    fn get(&self, index: usize) -> Option<&u8> {
        self.0.get(index)
    }

    fn iter(&self) -> impl Iterator<Item = &u8> {
        self.0.iter()
    }

    fn into_iter(self) -> impl Iterator<Item = u8> + 'static {
        // Use Cow to make it owned
        #[allow(clippy::unnecessary_to_owned)]
        self.0.into_owned().into_iter()
    }
}

impl fmt::Debug for ByteSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hexadecimal = encode_hexadecimal(&self.0);

        f.debug_tuple("ByteSlice").field(&hexadecimal).finish()
    }
}

impl fmt::Display for ByteSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = String::from_utf8_lossy(&self.0);
        f.write_str(&value)
    }
}

impl<'a> AsRef<ByteSlice<'a>> for ByteSlice<'a> {
    fn as_ref(&self) -> &ByteSlice<'a> {
        self
    }
}

impl<'a, T> Add<T> for ByteSlice<'_>
where
    T: AsRef<ByteSlice<'a>>,
{
    type Output = ByteSlice<'static>;

    fn add(self, rhs: T) -> Self::Output {
        &self + rhs
    }
}

impl<'a, T> Add<T> for &ByteSlice<'_>
where
    T: AsRef<ByteSlice<'a>>,
{
    type Output = ByteSlice<'static>;

    fn add(self, rhs: T) -> Self::Output {
        // Create a new iterator which chains the lhs and rhs together and copies the values
        let iter = self.iter().chain(rhs.as_ref().iter()).copied();

        // Create new struct from iterator
        ByteSlice::from_iter(iter)
    }
}
