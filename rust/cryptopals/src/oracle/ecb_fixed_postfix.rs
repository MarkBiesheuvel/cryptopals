use super::Oracle;
use crate::{aes, Bytes};

const FIXED_POSTFIX: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

/// Create a new oracle which will encrypt a plaintext.
///
/// During creation it will:
///  - randomly generate an encryption key
///
/// During encryption it will:
///  - concatenate the plaintext with a fixed postfix
///  - encrypt everything using AES ECB block cipher mode
pub struct EcbFixedPostfix {
    key: aes::Block,
    postfix: Bytes,
}

impl Default for EcbFixedPostfix {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Generate a random key
        let key = aes::Block::with_random_values(&mut rng);

        // Initialze postfix from base64
        let postfix = Bytes::try_from_base64(FIXED_POSTFIX).expect("Expected hardcoded base64 string to be valid");

        EcbFixedPostfix { key, postfix }
    }
}

impl Oracle for EcbFixedPostfix {
    fn encrypt(&self, plaintext: Bytes) -> Bytes {
        // Convert everything to iterators
        let plaintext = plaintext.iter();
        let postfix = self.postfix.iter();

        // Build a payload by chaining all the iterators and copy all the bytes
        // TODO: implement the Add trait for Bytes
        let payload = Bytes::from_iter(plaintext.chain(postfix).copied());

        // Encrypt using AES ECB block cipher mode
        aes::ecb::encrypt(&payload, &self.key)
    }
}
