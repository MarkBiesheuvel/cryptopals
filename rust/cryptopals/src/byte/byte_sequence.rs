use crate::CryptopalsError;
use error_stack::{ensure, Result};

/// Common functions for both `ByteSlice` and `ByteArray`
pub trait ByteSequence {
    /// The output type when creating a new instance from iterator
    type FromIterOutput;

    /// Custom FromIterator implementation so the return type can be specified
    fn from_iter<I>(iter: I) -> Self::FromIterOutput
    where
        I: IntoIterator<Item = u8>;

    /// Number of bytes stored
    fn length(&self) -> usize;

    /// Return a single byte at an index
    fn get(&self, index: usize) -> Option<&u8>;

    /// Return iterator over borrowed bytes
    fn iter(&self) -> impl Iterator<Item = &u8>;

    /// Return iterator over owned bytes
    fn into_iter(self) -> impl Iterator<Item = u8> + 'static;

    /// Create a new `ByteSequence` struct of the given length `N` which repeats the given `byte`
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let value = ByteSlice::with_repeated_byte_and_length(33, b'a');
    /// let expected = ByteSlice::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ///
    /// assert_eq!(value, expected);
    /// ```
    fn with_repeated_byte_and_length(length: usize, value: u8) -> Self::FromIterOutput {
        Self::from_iter((0..length).map(|_| value))
    }

    /// Create a new `ByteSequence` struct of the given `length` containing randoms values
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    /// use rand::Rng;
    ///
    /// let length = 42;
    /// let mut rng = rand::thread_rng();
    /// let value = ByteSlice::with_random_values_and_length(length, &mut rng);
    ///
    /// assert_eq!(value.length(), length);
    /// ```
    fn with_random_values_and_length(length: usize, rng: &mut impl rand::Rng) -> Self::FromIterOutput {
        Self::from_iter((0..length).map(|_| rng.gen()))
    }

    /// Single byte XOR
    fn single_byte_xor(&self, rhs: u8) -> Self::FromIterOutput {
        let iter = self.iter().map(|lhs| lhs ^ rhs);

        Self::from_iter(iter)
    }

    /// Hamming distance between two instances that implement the `ByteSequence` trait
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let text_1 = ByteSlice::from("this is a test");
    /// let text_2 = ByteSlice::from("wokka wokka!!!");
    ///
    /// assert_eq!(text_1.hamming_distance(&text_2)?, 37);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn hamming_distance(&self, other: &Self) -> Result<usize, CryptopalsError> {
        ensure!(self.length() == other.length(), CryptopalsError::UnequalLength);

        let difference = self
            .iter()
            .zip(other.iter())
            .map(|(lhs, rhs)| {
                // The bit difference between rhs and lhs
                let difference = lhs ^ rhs;

                // Iterate over each bit and sum the bits that are 1
                let number_of_bits = (0..8).map(|i: u8| (difference >> i) & 1).sum::<u8>();

                // For an individual byte the number of bits different is at most 8,
                // but when summing up a long array, the total might exceed the u8 primitive
                number_of_bits as usize
            })
            .sum();

        Ok(difference)
    }

    /// Whether a ByteSequence contains a specific byte value
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let value = ByteSlice::from("cryptopals");
    ///
    /// assert!(value.contains(&116));
    /// ```
    fn contains(&self, value: &u8) -> bool {
        self.iter().any(|byte| byte == value)
    }
}
