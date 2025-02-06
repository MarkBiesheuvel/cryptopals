use super::EncodingError;

pub fn decode_base64<S>(value: S) -> Result<Vec<u8>, EncodingError>
where
    S: AsRef<str>,
{
    // Get all characters
    let chars = value.as_ref().chars().collect::<Vec<_>>();

    // Retrieve the length of the string
    let input_length = chars.len();

    // Ensure the string length is divisible by four, as each three bytes consists of four characters
    if input_length % 4 != 0 {
        return Err(EncodingError::InvalidLength(input_length));
    }

    // Calculate desired output length
    let output_length = input_length * 3 / 4;

    // Since the size is known, we can create a Vec with desired capacity
    let mut bytes = Vec::with_capacity(output_length);

    // Parse per three bytes
    for i in (0..input_length).step_by(4) {
        // Get the characters
        let first_character = chars[i];
        let second_character = chars[i + 1];
        let third_character = chars[i + 2];
        let fourth_character = chars[i + 3];

        // Convert characters into 6-bit numbers
        let first_6_bit_number = char_to_u8(first_character)?;
        let second_6_bit_number = char_to_u8(second_character)?;

        // Use bit-shift and OR-operation to construct first 8-bit numbers
        bytes.push(first_6_bit_number << 2 | second_6_bit_number >> 4);

        if third_character == '=' {
            // If the third character is padding, there are no additional bytes
            break;
        }
        // Convert characters into 6-bit numbers
        let third_6_bit_number = char_to_u8(third_character)?;

        // Use bit-shift and OR-operation to construct second 8-bit numbers
        bytes.push(second_6_bit_number << 4 | third_6_bit_number >> 2);

        if fourth_character == '=' {
            // If the third character is padding, there are no additional bytes
            break;
        }
        // Convert characters into 6-bit numbers
        let fourth_6_bit_number = char_to_u8(fourth_character)?;

        // Use bit-shift and OR-operation to construct third 8-bit number
        bytes.push(third_6_bit_number << 6 | fourth_6_bit_number);
    }

    // Return Bytes struct
    Ok(bytes)
}

// Convert single base64 char to a 6-bit number
fn char_to_u8(character: char) -> Result<u8, EncodingError> {
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
        chr => return Err(EncodingError::InvalidCharacter(chr)),
    };

    Ok(number)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_length() {
        let result = decode_base64("bGlnaHQgd29yay4");

        assert!(result.is_err());
    }

    #[test]
    fn padding_1() {
        let bytes = decode_base64("bGlnaHQgd29yay4=").unwrap();
        let expected = "light work.";

        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn padding_2() {
        let bytes = decode_base64("bGlnaHQgd29yaw==").unwrap();
        let expected = "light work";

        assert_eq!(bytes, expected.as_bytes());
    }
}
