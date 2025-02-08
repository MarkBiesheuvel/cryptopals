use super::{Oracle, OracleError};
use crate::{aes, byte::*};
use byte_encoding_macro::base64;
use error_stack::Result;

const POSTFIX: [u8; 138] = base64!("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

/// An oracle which will encrypt a plaintext appended with a fixed string.
///
/// During creation it will:
///  - randomly generate an encryption key
///
/// During encryption it will:
///  - concatenate the plaintext with a fixed postfix
///  - encrypt everything using AES ECB block cipher mode
pub struct EcbFixedPostfixOracle {
    key: aes::Key,
    postfix: ByteSlice<'static>,
}

impl EcbFixedPostfixOracle {
    /// Return the base64 encoded postfix, so it can be verified by the test
    /// case.
    pub fn postfix(&self) -> &ByteSlice<'static> {
        &self.postfix
    }
}

impl Default for EcbFixedPostfixOracle {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Generate a random key
        let key = aes::Key::with_random_values(&mut rng);

        // Initialize postfix from base64
        let postfix = ByteSlice::from(POSTFIX.as_ref());

        EcbFixedPostfixOracle { key, postfix }
    }
}

impl Oracle for EcbFixedPostfixOracle {
    fn encrypt(&self, plaintext: ByteSlice<'_>) -> Result<ByteSlice<'static>, OracleError> {
        // Build a payload by adding the postfix to the plaintext
        let payload = plaintext + &self.postfix;

        // Encrypt using AES ECB block cipher mode
        let ciphertext = aes::ecb::encrypt(payload, &self.key);

        Ok(ciphertext)
    }
}
