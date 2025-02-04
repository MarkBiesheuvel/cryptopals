use std::borrow::Cow;
use std::convert::TryFrom;
use std::vec::Vec;

use error_stack::{bail, ensure, Report, Result};
use itermore::IterArrayChunks;

use crate::{byte::ByteSlice, CryptopalsError};

/// Base64 encoded string
#[derive(Debug)]
pub struct Base64<'a>(Cow<'a, str>);

impl From<String> for Base64<'static> {
    fn from(value: String) -> Self {
        Self(Cow::Owned(value))
    }
}

impl<'a> From<&'a str> for Base64<'a> {
    fn from(value: &'a str) -> Self {
        Self(Cow::Borrowed(value))
    }
}

impl TryFrom<Base64<'_>> for ByteSlice<'static> {
    type Error = Report<CryptopalsError>;

    fn try_from(value: Base64) -> core::result::Result<Self, Self::Error> {
        // Get the length of the string
        let length = value.0.len();

        // Input must be divisible by four
        ensure!(length % 4 == 0, CryptopalsError::InvalidBase64);

        // Parse each chunk of 2 characters
        let chunks = (value.0)
            .chars()
            .array_chunks()
            .map(|chunk| {
                // Deconstruct the chunk
                let [first_character, second_character, third_character, fourth_character] = chunk;

                // Convert characters into 6-bit numbers
                let first_6_bit_number = char_to_u8(first_character)?;
                let second_6_bit_number = char_to_u8(second_character)?;

                // Use bit-shift and OR-operation to construct first 8-bit numbers
                let first_byte = first_6_bit_number << 2 | second_6_bit_number >> 4;

                let bytes = if third_character == '=' {
                    // If the third character is padding, only return one byte
                    Vec::from([first_byte])
                } else {
                    // Convert characters into 6-bit numbers
                    let third_6_bit_number = char_to_u8(third_character)?;

                    // Use bit-shift and OR-operation to construct second 8-bit numbers
                    let second_byte = second_6_bit_number << 4 | third_6_bit_number >> 2;

                    if fourth_character == '=' {
                        // If the third character is padding, only return two bytes
                        Vec::from([first_byte, second_byte])
                    } else {
                        // Convert characters into 6-bit numbers
                        let fourth_6_bit_number = char_to_u8(fourth_character)?;

                        // Use bit-shift and OR-operation to construct third 8-bit number
                        let third_byte = third_6_bit_number << 6 | fourth_6_bit_number;

                        // Return three bytes
                        Vec::from([first_byte, second_byte, third_byte])
                    }
                };

                Ok(bytes)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Flatten list of chunks of numbers into single list of numbers
        let bytes = chunks.into_iter().flatten().collect::<Vec<_>>();

        // Return Bytes struct
        Ok(ByteSlice::from(bytes))
    }
}

// Convert single base64 char to a 6-bit number
fn char_to_u8(character: char) -> Result<u8, CryptopalsError> {
    let number = match character {
        'A' => 0,
        'B' => 1,
        'C' => 2,
        'D' => 3,
        'E' => 4,
        'F' => 5,
        'G' => 6,
        'H' => 7,
        'I' => 8,
        'J' => 9,
        'K' => 10,
        'L' => 11,
        'M' => 12,
        'N' => 13,
        'O' => 14,
        'P' => 15,
        'Q' => 16,
        'R' => 17,
        'S' => 18,
        'T' => 19,
        'U' => 20,
        'V' => 21,
        'W' => 22,
        'X' => 23,
        'Y' => 24,
        'Z' => 25,
        'a' => 26,
        'b' => 27,
        'c' => 28,
        'd' => 29,
        'e' => 30,
        'f' => 31,
        'g' => 32,
        'h' => 33,
        'i' => 34,
        'j' => 35,
        'k' => 36,
        'l' => 37,
        'm' => 38,
        'n' => 39,
        'o' => 40,
        'p' => 41,
        'q' => 42,
        'r' => 43,
        's' => 44,
        't' => 45,
        'u' => 46,
        'v' => 47,
        'w' => 48,
        'x' => 49,
        'y' => 50,
        'z' => 51,
        '0' => 52,
        '1' => 53,
        '2' => 54,
        '3' => 55,
        '4' => 56,
        '5' => 57,
        '6' => 58,
        '7' => 59,
        '8' => 60,
        '9' => 61,
        '+' => 62,
        '/' => 63,
        _ => {
            bail!(CryptopalsError::InvalidBase64);
        }
    };

    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_length() {
        let result = ByteSlice::try_from(Base64::from("bGlnaHQgd29yay4"));

        assert!(result.is_err());
    }

    #[test]
    fn padding_1() {
        let result = ByteSlice::try_from(Base64::from("bGlnaHQgd29yay4="));
        let expected = ByteSlice::from("light work.");

        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn padding_2() {
        let result = ByteSlice::try_from(Base64::from("bGlnaHQgd29yaw=="));
        let expected = ByteSlice::from("light work");

        assert_eq!(result.unwrap(), expected);
    }
}
