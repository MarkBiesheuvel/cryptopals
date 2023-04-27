use std::fmt;

use super::functions::{base64, hexadecimal};
use super::CryptopalsError;

/// Plaintext or ciphertext without any guarantees regarding block size
#[derive(Eq, PartialEq, PartialOrd, Ord)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn try_from_hexadecimal(value: &str) -> Result<Bytes, CryptopalsError> {
        // Get the length of the string
        let length = value.len();

        // Input must be even
        if length % 2 != 0 {
            return Err(CryptopalsError::InvalidHexadecimal);
        }

        // Parse each chunk of 2 characters
        let bytes = value
            .chars()
            .array_chunks()
            .map(|chunk| {
                // Deconstruct the chunk
                let [first_character, second_character] = chunk;

                // Convert characters into 4-bit numbers
                let first_4_bit_number = hexadecimal(first_character)?;
                let second_4_bit_number = hexadecimal(second_character)?;

                // Use bit-shift and OR-operation to construct one 8-bit number
                Ok(first_4_bit_number << 4 | second_4_bit_number)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Return
        Ok(Bytes(bytes))
    }

    pub fn try_from_base64(value: &str) -> Result<Bytes, CryptopalsError> {
        // Get the length of the string
        let length = value.len();

        // Input must be divisible by four
        if length % 4 != 0 {
            return Err(CryptopalsError::InvalidBase64);
        }

        // Parse each chunk of 2 characters
        let chunks = value
            .chars()
            .array_chunks()
            .map(|chunk| {
                // Deconstruct the chunk
                let [first_character, second_character, third_character, fourth_character] = chunk;

                // Convert characters into 6-bit numbers
                let first_6_bit_number = base64(first_character)?;
                let second_6_bit_number = base64(second_character)?;
                let third_6_bit_number = base64(third_character)?;
                let fourth_6_bit_number = base64(fourth_character)?;

                // TODO: handle padding by returning a Vec instead of [u8; 3]

                // Use bit-shift and OR-operation to construct three 8-bit numbers
                Ok([
                    first_6_bit_number << 2 | second_6_bit_number >> 4,
                    second_6_bit_number << 4 | third_6_bit_number >> 2,
                    third_6_bit_number << 6 | fourth_6_bit_number,
                ])
            })
            .collect::<Result<Vec<_>, _>>()?;

        let bytes = chunks.into_iter().flatten().collect();

        Ok(Bytes(bytes))
    }
}

impl fmt::Debug for Bytes {
    /// Custom debug function which displays Bytes as a human readable string
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut tuple = f.debug_tuple("Bytes");

        match String::from_utf8(self.0.clone()) {
            Ok(value) => {
                tuple.field(&value);
            }
            Err(_) => {
                // TODO: find a different way of representing invalid UTF-8 string
                tuple.field(&self.0);
            }
        };

        tuple.finish()
    }
}
