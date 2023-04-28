use std::convert::From;
use std::fmt;
use std::vec::Vec;

use crate::CryptopalsError;

/// Plaintext or ciphertext without any guarantees regarding block size
#[derive(Eq, PartialEq)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn fixed_xor(&self, other: &Bytes) -> Result<Bytes, CryptopalsError> {
        if self.0.len() != other.0.len() {
            return Err(CryptopalsError::UnequalLength);
        }

        let bytes = (self.0.iter())
            .zip(other.0.iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect();

        Ok(Bytes(bytes))
    }

    pub fn single_byte_xor(&self, rhs: u8) -> Bytes {
        let bytes = self.0.iter().map(|lhs| lhs ^ rhs).collect();

        Bytes(bytes)
    }
}

impl<V> From<V> for Bytes
where
    V: Into<Vec<u8>>,
{
    /// Construct a Bytes struct from antyhing that can be turned into a `Vec<u8>`, like for example a &str
    fn from(value: V) -> Self {
        Bytes(value.into())
    }
}

impl fmt::Debug for Bytes {
    /// Custom debug function which displays Bytes as a human readable string
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Open
        writeln!(f, "Bytes {{")?;

        // If it is possible to express as a string, add it as a "field"
        if let Ok(value) = String::from_utf8(self.0.clone()) {
            writeln!(f, "    string_repr: {:?}", value)?;
        };

        // Single line list of raw bytes
        // NOTE: fmt::DebugStruct will print each number in vector on a new lines, hence
        // a custom implementation
        writeln!(f, "    raw_bytes: {:?}", self.0)?;

        // Calculated length
        writeln!(f, "    length: {:?}", self.0.len())?;

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

    #[test]
    fn single_byte_xor() {
        let value = Bytes::from("Hello, World");
        let expected = Bytes::from([98, 79, 70, 70, 69, 6, 10, 125, 69, 88, 70, 78]);

        assert_eq!(value.single_byte_xor(42), expected);
    }
}
