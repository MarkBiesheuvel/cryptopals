use std::convert::TryFrom;
use std::vec::Vec;

use itermore::IterArrayChunks;
use error_stack::{bail, ensure, Report, Result};

use crate::{Bytes, CryptopalsError};

/// Hexadecimal encoded string
#[derive(Debug)]
pub struct Hexadecimal(String);

impl<S> From<S> for Hexadecimal
where
    S: Into<String>,
{
    fn from(value: S) -> Hexadecimal {
        Hexadecimal(value.into())
    }
}

impl TryFrom<Hexadecimal> for Bytes {
    type Error = Report<CryptopalsError>;

    fn try_from(mut value: Hexadecimal) -> core::result::Result<Self, Self::Error> {
        // Remove whitespaces for ease of use
        value.0.retain(|c| !c.is_whitespace());

        // Get the length of the string
        let length = value.0.len();

        // Input must be even
        ensure!(length % 2 == 0, CryptopalsError::InvalidHexadecimal);

        // Parse each chunk of 2 characters
        let bytes = (value.0)
            .chars()
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
        Ok(Bytes::from(bytes))
    }
}

impl From<&Bytes> for Hexadecimal {
    fn from(value: &Bytes) -> Self {
        let value = value
            .iter()
            .map(|number| {
                let second_character = u8_to_char(number & 0b00001111).unwrap();
                let first_character = u8_to_char(number >> 4).unwrap();

                format!("{first_character}{second_character}")
            })
            .collect::<Vec<_>>()
            .join(" ");

        Hexadecimal(value)
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

/// Convert single 4 bit number into hexadecimal char
fn u8_to_char(number: u8) -> Result<char, CryptopalsError> {
    let character = match number {
        0 => '0',
        1 => '1',
        2 => '2',
        3 => '3',
        4 => '4',
        5 => '5',
        6 => '6',
        7 => '7',
        8 => '8',
        9 => '9',
        10 => 'A',
        11 => 'B',
        12 => 'C',
        13 => 'D',
        14 => 'E',
        15 => 'F',
        _ => {
            bail!(CryptopalsError::InvalidHexadecimal);
        }
    };

    Ok(character)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_length() {
        let result = Bytes::try_from(Hexadecimal::from("48656c6c6f2c20576f726c642"));

        assert!(result.is_err());
    }

    #[test]
    fn lowercase() {
        let result = Bytes::try_from(Hexadecimal::from("48656c6c6f2c20576f726c6421"));
        let expected = Bytes::from("Hello, World!");

        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn uppercase() {
        let result = Bytes::try_from(Hexadecimal::from("48656C6C6f2C20576F726C6421"));
        let expected = Bytes::from("Hello, World!");

        assert_eq!(result.unwrap(), expected);
    }
}
