use super::{Oracle, OracleError};
use crate::{aes, byte::*};
use error_stack::{ensure, Result};

// Special characters
const CHARACTER_SEMICOLON: char = ';';
const CHARACTER_EQUALS_SIGN: char = '=';
const BYTE_SEMICOLON: u8 = CHARACTER_SEMICOLON as u8;
const BYTE_EQUALS_SIGN: u8 = CHARACTER_EQUALS_SIGN as u8;

/// An oracle which takes a plaintext and encrypts it.
///
/// During creation it will:
///  - randomly generate an encryption key
///
/// During encryption it will:
///  - concatenate the plaintext with a fixed prefix
///  - concatenate the plaintext with a fixed postfix
pub struct UserDataOracle {
    key: aes::Key,
    prefix: ByteSlice<'static>,
    postfix: ByteSlice<'static>,
}

impl Default for UserDataOracle {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Generate a random key
        let key = aes::Key::with_random_values(&mut rng);

        // Initialize pre- and postfix
        let prefix = ByteSlice::from("comment1=cooking%20MCs;userdata=");
        let postfix = ByteSlice::from(";comment2=%20like%20a%20pound%20of%20bacon");

        UserDataOracle { key, prefix, postfix }
    }
}

impl Oracle for UserDataOracle {
    fn encrypt(&self, plaintext: ByteSlice<'_>) -> Result<ByteSlice<'static>, OracleError> {
        // Input validation
        ensure!(!plaintext.contains(&BYTE_SEMICOLON), OracleError::DisallowedCharacter(CHARACTER_SEMICOLON));
        ensure!(!plaintext.contains(&BYTE_EQUALS_SIGN), OracleError::DisallowedCharacter(CHARACTER_EQUALS_SIGN));

        // Build a payload by adding the postfix to the plaintext
        let payload = &self.prefix + plaintext + &self.postfix;

        // Encrypt
        let ciphertext = aes::cbc::encrypt(payload, &self.key);

        Ok(ciphertext)
    }
}
