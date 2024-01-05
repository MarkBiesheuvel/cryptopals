use crate::{aes, Bytes, Oracle};

const DEFAULT_CHARACTER: char = 'U';

// List of printable ASCII characters
const PRINTABLE_CHARACTERS: [u8; 97] = [
    9, 10, 13, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
    58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86,
    87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125,
];

fn ciphertext_length<O: Oracle>(oracle: &O, plaintext_length: usize) -> usize {
    let plaintext = Bytes::with_repeated_character(plaintext_length, DEFAULT_CHARACTER);
    let ciphertext = oracle.encrypt(plaintext);
    ciphertext.length()
}

/// Attack the the postfix of an Oracle encrypting with ECB mode
pub fn attack_ecb_fixed_postfix<O: Oracle>(oracle: &O) -> Bytes {
    // Initialize all variables before entering the while loop
    let mut plaintext_length = 0;
    let mut current_ciphertext_length = ciphertext_length(oracle, plaintext_length);
    let mut previous_ciphertext_length;

    loop {
        // Recalculate the values for new plaintext length
        previous_ciphertext_length = current_ciphertext_length;
        current_ciphertext_length = ciphertext_length(oracle, plaintext_length);

        if previous_ciphertext_length != current_ciphertext_length {
            break;
        }

        // Increase the length of the plaintext
        plaintext_length += 1;
    }

    // The block length is equal to the difference in ciphertext length
    // Since we only added one character, the padding extended the length by one
    // block
    let block_length = current_ciphertext_length - previous_ciphertext_length;
    assert_eq!(block_length, aes::BLOCK_LENGTH);

    // Calculate the length of the postfix string that was appended to the plaintext
    // The current plaintext length plus postfix length fit exactly in the block
    // size and therefore needed another block of padding. Use the previous
    // ciphertext length to determine how many blocks that was.
    let postfix_length = previous_ciphertext_length - plaintext_length;

    // Brute force each character of the fixed postfix one by one
    #[allow(clippy::never_loop)]
    for byte_index in 0..postfix_length {
        // Calculate the block number within the plaintext/cipher which will contain the
        // character we are looking for
        let block_index = byte_index / block_length;

        // Prefix all plaintexts with a specific number of bytes to position the
        // character we are looking for in the last position of a block in the
        // ciphertext
        let prefix_length = (block_index + 1) * block_length - byte_index - 1;
        let prefix = Bytes::with_repeated_character(prefix_length, DEFAULT_CHARACTER);

        let plaintexts = PRINTABLE_CHARACTERS
            .into_iter()
            .map(|byte| {
                // TODO: finally implement Add trait on Bytes
                let single_byte = Bytes::from([byte]);
                let iter = prefix.iter().chain(single_byte.iter()).copied();
                Bytes::from_iter(iter)
            })
            .collect::<Vec<_>>();

        dbg!(plaintexts);
        break;
    }

    Bytes::from([])
}
