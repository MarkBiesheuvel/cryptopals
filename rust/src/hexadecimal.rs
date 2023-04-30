use std::convert::TryFrom;
use std::vec::Vec;

use super::{Bytes, CryptopalsError};

/// Hexadecimal encoded string
#[derive(Debug)]
pub struct Hexadecimal<'a>(pub &'a str);

impl TryFrom<Hexadecimal<'_>> for Bytes {
    type Error = CryptopalsError;

    fn try_from(value: Hexadecimal<'_>) -> Result<Self, Self::Error> {
        // Get the length of the string
        let length = value.0.len();

        // Input must be even
        if length % 2 != 0 {
            return Err(CryptopalsError::InvalidHexadecimal);
        }

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

// Convert single hexadecimal char to a 4-bit number
pub fn char_to_u8(character: char) -> Result<u8, CryptopalsError> {
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
            return Err(CryptopalsError::InvalidHexadecimal);
        }
    };

    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_length() {
        let error = Bytes::try_from(Hexadecimal("48656c6c6f2c20576f726c642")).unwrap_err();
        let expected = CryptopalsError::InvalidHexadecimal;

        assert_eq!(error, expected);
    }

    #[test]
    fn lowercase() {
        let value = Bytes::try_from(Hexadecimal("48656c6c6f2c20576f726c6421")).unwrap();
        let expected = Bytes::from("Hello, World!");

        assert_eq!(value, expected);
    }

    #[test]
    fn uppercase() {
        let value = Bytes::try_from(Hexadecimal("48656C6C6f2C20576F726C6421")).unwrap();
        let expected = Bytes::from("Hello, World!");

        assert_eq!(value, expected);
    }
}
