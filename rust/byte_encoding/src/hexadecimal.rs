use super::EncodingError;

pub fn decode_hexadecimal<S>(value: S) -> Result<Vec<u8>, EncodingError>
where
    S: AsRef<str>,
{
    // Remove all whitespace characters
    let chars = value
        .as_ref()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<Vec<_>>();

    // Retrieve the length of the string
    let input_length = chars.len();

    // Ensure the string length is even, as each byte consists of two characters
    if input_length % 2 != 0 {
        return Err(EncodingError::InvalidLength(input_length));
    }

    // Calculate desired output length
    let output_length = input_length / 2;

    // Since the size is known, we can create a Vec with desired capacity
    let mut bytes = Vec::with_capacity(output_length);

    // Parse byte by byte
    for i in (0..input_length).step_by(2) {
        // Get the characters
        let first_character = chars[i];
        let second_character = chars[i + 1];

        // Convert characters into 4-bit numbers
        let first_4_bit_number = char_to_u8(first_character)?;
        let second_4_bit_number = char_to_u8(second_character)?;

        // Construct and append byte
        bytes.push(first_4_bit_number << 4 | second_4_bit_number);
    }

    Ok(bytes)
}

pub fn encode_hexadecimal<B>(value: B) -> String
where
    B: AsRef<[u8]>,
{
    value
        .as_ref()
        .iter()
        .map(|number| {
            let second_character = u8_to_char(number & 0b00001111);
            let first_character = u8_to_char(number >> 4);
            format!("{first_character}{second_character}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

// Convert single hexadecimal char to a 4-bit number
fn char_to_u8(character: char) -> Result<u8, EncodingError> {
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
        chr => return Err(EncodingError::InvalidCharacter(chr)),
    };

    Ok(number)
}

// Convert single 4 bit number into hexadecimal char
fn u8_to_char(number: u8) -> char {
    match number {
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
            panic!("internal method should only receive numbers between 0 and 15 inclusive");
        }
    }
}

// TODO: some unit tests
