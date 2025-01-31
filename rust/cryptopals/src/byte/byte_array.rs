use super::{ByteSequence, ByteSlice};
use crate::CryptopalsError;
use error_stack::{ensure, Report};
use std::ops::{BitXor, Index, IndexMut};

/// A statically sized collection of bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteArray<const N: usize>([u8; N]);

impl<const N: usize> From<[u8; N]> for ByteArray<N> {
    /// Create a `ByteArray` from static array of `u8`
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let static_array = [99, 114, 121, 112, 116, 111, 112, 97, 108, 115];
    /// let value = ByteArray::from(static_array);
    ///
    /// // assert_eq!(value.get(1), Some(&114));
    /// ```
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> TryFrom<ByteSlice<'_>> for ByteArray<N> {
    type Error = Report<CryptopalsError>;

    /// Try to convert a dynamically sized byte sequence into a statically sized byte sequence.
    ///
    /// Only use this for case where you know the length of a byte sequence, but this could not be expressed via the
    /// type system at compile time. For example, when creating a byte array from a static string. Since the string is
    /// static the length is guaranteed, but it is not known by the compiler.
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let value = ByteArray::try_from(ByteSlice::from("cryptopals"))?;
    /// let expected = ByteArray::from([99, 114, 121, 112, 116, 111, 112, 97, 108, 115]);
    ///
    /// assert_eq!(value, expected);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn try_from(value: ByteSlice) -> core::result::Result<Self, Self::Error> {
        // Make sure the `ByteSlice` matches the length `N`
        ensure!(value.length() == N, CryptopalsError::InvalidLength);

        // Initialize static array
        let mut bytes = [0; N];

        // Move over each item
        for (k, v) in bytes.iter_mut().zip(value.into_iter()) {
            *k = v;
        }

        Ok(ByteArray(bytes))
    }
}

impl<const N: usize> ByteSequence for ByteArray<N> {
    type FromIterOutput = ByteArray<N>;

    /// Construct a `ByteArray` struct from an iterator over `u8` values.
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let value_1 = ByteSlice::from("abcdefghijklmnopqrstuvwxyz");
    /// let value_1 = ByteArray::<26>::try_from(value_1)?;
    ///
    /// let value_2 = ByteArray::<26>::from_iter(97..);
    ///
    /// assert_eq!(value_1, value_2);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    fn from_iter<I>(iter: I) -> Self::FromIterOutput
    where
        I: IntoIterator<Item = u8>,
    {
        // Initialize static array
        let mut bytes = [0; N];

        // Limit the iterator to the maximum size
        let iter = iter.into_iter().take(N);

        // Move over each item
        for (k, v) in bytes.iter_mut().zip(iter) {
            *k = v;
        }

        // TODO: automatically pad?

        ByteArray(bytes)
    }

    /// Return number of bytes stored, which is static
    fn length(&self) -> usize {
        N
    }

    /// Return a single byte at an index
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let value = ByteArray::from([99, 114, 121, 112, 116, 111, 112, 97, 108, 115]);
    ///
    /// assert_eq!(value.get(3), Some(&112));
    /// ```
    fn get(&self, index: usize) -> Option<&u8> {
        self.0.get(index)
    }

    fn iter<'a>(&'a self) -> impl Iterator<Item = &'a u8> + 'a {
        self.0.iter()
    }

    fn into_iter(self) -> impl Iterator<Item = u8> + 'static {
        self.0.into_iter()
    }
}

impl<const N: usize> ByteArray<N> {
    /// Create a new `ByteArray` struct which repeats the given `byte`
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    ///
    /// let value = ByteArray::<16>::with_repeated_byte(42);
    /// let expected = Some(&42);
    ///
    /// assert_eq!(value.get(4), expected);
    /// ```
    pub fn with_repeated_byte(value: u8) -> <ByteArray<N> as ByteSequence>::FromIterOutput {
        ByteArray::with_repeated_byte_and_length(N, value)
    }

    /// Create a new `ByteArray` struct  containing randoms values
    ///
    /// ## Examples
    /// ```
    /// use cryptopals::byte::*;
    /// use rand::Rng;
    ///
    /// const LENGTH: usize = 32;
    /// let mut rng = rand::thread_rng();
    /// let value = ByteArray::<LENGTH>::with_random_values(&mut rng);
    ///
    /// assert_eq!(value.length(), LENGTH);
    /// ```
    pub fn with_random_values(rng: &mut impl rand::Rng) -> <ByteArray<N> as ByteSequence>::FromIterOutput {
        ByteArray::with_random_values_and_length(N, rng)
    }
}

impl<const N: usize> BitXor for ByteArray<N> {
    type Output = ByteArray<N>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        // Xor each byte of lhs and rhs
        let iter = self.iter().zip(rhs.iter()).map(|(lhs, rhs)| lhs ^ rhs);

        ByteArray::from_iter(iter)
    }
}

impl<const N: usize> Index<usize> for ByteArray<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.0.index(index)
    }
}

impl<const N: usize> IndexMut<usize> for ByteArray<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.0.index_mut(index)
    }
}
