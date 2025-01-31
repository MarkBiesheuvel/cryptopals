use std::borrow::Cow;
use std::convert::TryFrom;
use std::vec::Vec;

use error_stack::{bail, ensure, Report, Result};
use itermore::IterArrayChunks;

use crate::{byte::ByteSlice, CryptopalsError};

/// Hexadecimal encoded string
#[derive(Debug)]
pub struct Hexadecimal<'a>(Cow<'a, str>);

impl From<String> for Hexadecimal<'_> {
    fn from(value: String) -> Hexadecimal<'static> {
        Hexadecimal(Cow::Owned(value))
    }
}

impl<'a> From<&'a str> for Hexadecimal<'a> {
    fn from(value: &'a str) -> Hexadecimal<'a> {
        Hexadecimal(Cow::Borrowed(value))
    }
}

impl TryFrom<Hexadecimal<'_>> for ByteSlice<'static> {
    type Error = Report<CryptopalsError>;

    fn try_from(value: Hexadecimal) -> core::result::Result<Self, Self::Error> {
        let characters = value
            .0
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<Vec<_>>();

        // Input must be even
        ensure!(characters.len() % 2 == 0, CryptopalsError::InvalidHexadecimal);

        // Parse each chunk of 2 characters
        let bytes = characters
            .into_iter()
            .array_chunks()
            .map(|chunk| {
                // Deconstruct the chunk
                let [first_character, second_character] = chunk;

                // Convert characters into 4-bit numbers
                let first_4_bit_number = char_to_u8(first_character)?;
                let second_4_bit_number = char_to_u8(second_character)?;

                // Use bit-shift and OR-operation to construct one 8-bit number
                Ok(first_4_bit_number << 4 | second_4_bit_number)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Return Bytes struct
        Ok(ByteSlice::from(bytes))
    }
}

// Convert single hexadecimal char to a 4-bit number
fn char_to_u8(character: char) -> Result<u8, CryptopalsError> {
    let number = match character {
        '0' => 0,
        '1' => 1,
        '2' => 2,
        '3' => 3,
        '4' => 4,
        '5' => 5,
        '6' => 6,
        '7' => 7,
        '8' => 8,
        '9' => 9,
        'a' | 'A' => 10,
        'b' | 'B' => 11,
        'c' | 'C' => 12,
        'd' | 'D' => 13,
        'e' | 'E' => 14,
        'f' | 'F' => 15,
        _ => {
            bail!(CryptopalsError::InvalidHexadecimal);
        }
    };

    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_length() {
        let result = ByteSlice::try_from(Hexadecimal::from("48656c6c6f2c20576f726c642"));

        assert!(result.is_err());
    }

    #[test]
    fn lowercase() {
        let result = ByteSlice::try_from(Hexadecimal::from("48656c6c6f2c20576f726c6421"));
        let expected = ByteSlice::from("Hello, World!");

        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn uppercase() {
        let result = ByteSlice::try_from(Hexadecimal::from("48656C6C6f2C20576F726C6421"));
        let expected = ByteSlice::from("Hello, World!");

        assert_eq!(result.unwrap(), expected);
    }
}
