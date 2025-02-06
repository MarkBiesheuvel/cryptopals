//! Advanced Encryption Standard (AES)
//!
//! ## Examples
//! ```
//! use cryptopals::{aes, byte::*};
//!
//! let key = aes::Key::from(*b"YELLOW SUBMARINE");
//! let plaintext = ByteSlice::from("cryptopals");
//!
//! // Since the plaintext is less than 16 bytes (one AES block),
//! // there is no difference between ECB and CBC mode
//! assert_eq!(aes::ecb::encrypt(plaintext.clone(), &key), aes::cbc::encrypt(plaintext.clone(), &key));
//! ```
pub use block::{Block, BLOCK_LENGTH};
pub use key::Key;

mod block;
mod byte_operator;
pub mod cbc;
pub mod ecb;
mod key;

/// The block cipher mode of operation of AES
#[derive(Debug, PartialEq, Eq)]
pub enum BlockMode {
    /// Electronic codebook (ECB) mode
    Ecb,
    /// Cipher block chaining (CBC) mode
    Cbc,
}

// Following the steps of https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
#[cfg(test)]
mod tests {
    use super::*;
    use byte_encoding_macro::hex;

    #[test]
    fn roundkey() {
        let key = Key::from(*b"Thats my Kung Fu");

        let expected_roundkeys = [
            hex!("54 68 61 74 73 20 6D 79 20 4B 75 6E 67 20 46 75"),
            hex!("E2 32 FC F1 91 12 91 88 B1 59 E4 E6 D6 79 A2 93"),
            hex!("56 08 20 07 C7 1A B1 8F 76 43 55 69 A0 3A F7 FA"),
            hex!("D2 60 0D E7 15 7A BC 68 63 39 E9 01 C3 03 1E FB"),
            hex!("A1 12 02 C9 B4 68 BE A1 D7 51 57 A0 14 52 49 5B"),
            hex!("B1 29 3B 33 05 41 85 92 D2 10 D2 32 C6 42 9B 69"),
            hex!("BD 3D C2 87 B8 7C 47 15 6A 6C 95 27 AC 2E 0E 4E"), // Mistake in PDF
            hex!("CC 96 ED 16 74 EA AA 03 1E 86 3F 24 B2 A8 31 6A"),
            hex!("8E 51 EF 21 FA BB 45 22 E4 3D 7A 06 56 95 4B 6C"),
            hex!("BF E2 BF 90 45 59 FA B2 A1 64 80 B4 F7 F1 CB D8"),
            hex!("28 FD DE F8 6D A4 24 4A CC C0 A4 FE 3B 31 6F 26"),
        ]
        .into_iter()
        .map(Block::from);

        // Verify each roundkey against expected value
        for ((_round_number, round_key), expected) in key.rounds().zip(expected_roundkeys) {
            assert_eq!(round_key, &expected);
        }
    }

    #[test]
    fn manual_rounds() {
        let key = Key::from(*b"Thats my Kung Fu");
        let plaintext = Block::from(*b"Two One Nine Two");

        // Expected state after each step
        let mut expected_states = [
            hex!("00 1F 0E 54 3C 4E 08 59 6E 22 1B 0B 47 74 31 1A"),
            hex!("63 C0 AB 20 EB 2F 30 CB 9F 93 AF 2B A0 92 C7 A2"),
            hex!("63 2F AF A2 EB 93 C7 20 9F 92 AB CB A0 C0 30 2B"),
            hex!("BA 75 F4 7A 84 A4 8D 32 E8 8D 06 0E 1B 40 7D 5D"),
            hex!("58 47 08 8B 15 B6 1C BA 59 D4 E2 E8 CD 39 DF CE"),
            hex!("6A A0 30 3D 59 4E 9C F4 CB 48 98 9B BD 12 9E 8B"),
            hex!("6A 4E 98 8B 59 48 9E 3D CB 12 30 F4 BD A0 9C 9B"), // Mistake in PDF
            hex!("15 CE 89 65 C9 4D 71 47 7F 4B BE 97 9D C2 88 CD"),
            hex!("43 C6 A9 62 0E 57 C0 C8 09 08 EB FE 3D F8 7F 37"),
        ]
        .into_iter()
        .map(Block::from);

        // Start with plaintext
        let mut state = plaintext;
        let mut rounds = key.rounds();

        // Round 0 - Apply roundkey
        state ^= rounds.next().unwrap().1;
        assert_eq!(state, expected_states.next().unwrap());

        // Round 1 - Substitution bytes
        state.sub_bytes();
        assert_eq!(state, expected_states.next().unwrap());

        // Round 1 - Shift rows
        state.shift_rows();
        assert_eq!(state, expected_states.next().unwrap());

        // Round 1 - Mix columns
        state.mix_columns();
        assert_eq!(state, expected_states.next().unwrap());

        // Round 1 - Apply roundkey
        state ^= rounds.next().unwrap().1;
        assert_eq!(state, expected_states.next().unwrap());

        // Round 2 - Substitution bytes
        state.sub_bytes();
        assert_eq!(state, expected_states.next().unwrap());

        // Round 2 - Shift rows
        state.shift_rows();
        assert_eq!(state, expected_states.next().unwrap());

        // Round 2 - Mix columns
        state.mix_columns();
        assert_eq!(state, expected_states.next().unwrap());

        // Round 2 - Apply roundkey
        state ^= rounds.next().unwrap().1;
        assert_eq!(state, expected_states.next().unwrap());
    }

    #[test]
    fn manual_rounds_reverse() {
        let key = Key::from(*b"Thats my Kung Fu");
        let ciphertext = Block::from(hex!("29 C3 50 5F 57 14 20 F6 40 22 99 B3 1A 02 D7 3A"));

        let mut expected_states = [
            hex!("01 3E 8E A7 3A B0 04 BC 8C E2 3D 4D 21 33 B8 1C"),
            hex!("01 33 3D BC 3A 3E B8 4D 8C B0 8E 1C 21 E2 04 A7"),
            hex!("09 66 8B 78 A2 D1 9A 65 F0 FC E6 C4 7B 3B 30 89"),
            hex!("B6 84 34 E8 E7 88 60 D7 51 98 66 70 8C CA FB 51"),
            hex!("33 8B 76 20 51 66 7D 92 79 8F EB C2 0A 3F BE 67"),
            hex!("33 3F EB 92 51 8B BE C2 79 66 76 67 0A 8F 7D 20"),
            hex!("66 25 3C 74 70 CE 5A A8 AF D3 0F 0A A3 73 13 54"),
        ]
        .into_iter()
        .map(Block::from);

        // Start with plaintext
        let mut state = ciphertext;
        let mut rounds = key.rounds().rev();

        // Round 10 - Apply roundkey
        state ^= rounds.next().unwrap().1;
        assert_eq!(state, expected_states.next().unwrap());

        // Round 10 - Inverse shift rows
        state.inverse_shift_rows();
        assert_eq!(state, expected_states.next().unwrap());

        // Round 10 - Inverse substitution bytes
        state.inverse_sub_bytes();
        assert_eq!(state, expected_states.next().unwrap());

        // Round 9 - Apply roundkey
        state ^= rounds.next().unwrap().1;
        assert_eq!(state, expected_states.next().unwrap());

        // Round 9 - Inverse mix columns
        state.inverse_mix_columns();
        assert_eq!(state, expected_states.next().unwrap());

        // Round 9 - Inverse shift rows
        state.inverse_shift_rows();
        assert_eq!(state, expected_states.next().unwrap());

        // Round 9 - Inverse substitution bytes
        state.inverse_sub_bytes();
        assert_eq!(state, expected_states.next().unwrap());
    }

    #[test]
    fn start_to_finish() {
        let key = Key::from(*b"Thats my Kung Fu");
        let plaintext = Block::from(*b"Two One Nine Two");

        // Perform encryption operation from start to finish
        let mut block = plaintext.clone();
        block.encrypt(&key);

        // Expected ciphertext
        let expected = Block::from(hex!("29 C3 50 5F 57 14 20 F6 40 22 99 B3 1A 02 D7 3A"));
        assert_eq!(block, expected);

        // Perform encryption operation from start to finish
        block.decrypt(&key);
        assert_eq!(block, plaintext);
    }
}
