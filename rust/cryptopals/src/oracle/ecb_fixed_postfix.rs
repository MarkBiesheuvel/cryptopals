use super::{Oracle, OracleError};
use crate::{aes, byte::*};
use byte_encoding_macro::base64;
use error_stack::Result;
use rand::Rng;

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
    prefix: ByteSlice<'static>,
    postfix: ByteSlice<'static>,
}

impl EcbFixedPostfixOracle {
    /// Return the base64 encoded postfix, so it can be verified by the test case.
    pub fn postfix(&self) -> &ByteSlice<'static> {
        &self.postfix
    }

    /// Create oracle with a random prefix instead of an empty prefix
    pub fn with_random_prefix() -> Self {
        // When the prefix length is not specified, a random one is generated
        EcbFixedPostfixOracle::new(None)
    }

    fn new(prefix_length_option: Option<usize>) -> Self {
        let mut rng = rand::thread_rng();

        // Use given length are randomly generate one
        let prefix_length = match prefix_length_option {
            Some(length) => length,
            None => rng.gen_range(1..32),
        };

        let prefix = ByteSlice::with_random_values_and_length(prefix_length, &mut rng);

        // Generate a random key
        let key = aes::Key::with_random_values(&mut rng);

        // Initialize postfix from base64
        let postfix = ByteSlice::from(POSTFIX.as_ref());

        EcbFixedPostfixOracle { key, prefix, postfix }
    }
}

impl Default for EcbFixedPostfixOracle {
    fn default() -> Self {
        // By default, the prefix length is zero
        EcbFixedPostfixOracle::new(Some(0))
    }
}

impl Oracle for EcbFixedPostfixOracle {
    fn encrypt(&self, plaintext: ByteSlice<'_>) -> Result<ByteSlice<'static>, OracleError> {
        // Build a payload by adding the postfix to the plaintext
        let payload = &self.prefix + plaintext + &self.postfix;

        // Encrypt using AES ECB block cipher mode
        let ciphertext = aes::ecb::encrypt(payload, &self.key);

        Ok(ciphertext)
    }
}
