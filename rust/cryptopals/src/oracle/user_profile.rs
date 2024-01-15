use std::cell::RefCell;

use error_stack::{ensure, Result};

use super::{Oracle, OracleError};
use crate::{aes, Bytes};

// Special charactors for URL-encoding
const CHARACTER_AMPERSAND: u8 = b'&';
const CHARACTER_EQUALS_SIGN: u8 = b'=';

/// An oracle which takes a plaintext email address and creates an encrypted
/// token for it.
///
/// During creation it will:
///  - randomly generate an encryption key
pub struct UserProfile {
    key: aes::Block,
    prefix: Bytes,
    latest_id: RefCell<usize>,
}

impl Default for UserProfile {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Generate a random key
        let key = aes::Block::with_random_values(&mut rng);

        // Prefix will always be the same, so we can already make a Bytes struct
        let prefix = Bytes::from("email=");

        // Auto increment the UUID of the user, but start with a number that won't
        // likely impact the padding of the ciphertext
        let latest_id = RefCell::new(1_000);

        UserProfile {
            key,
            prefix,
            latest_id,
        }
    }
}

impl Oracle for UserProfile {
    fn encrypt(&self, email: Bytes) -> Result<Bytes, OracleError> {
        // Input validation
        ensure!(!email.contains(&CHARACTER_AMPERSAND), OracleError::DisallowedCharacterInEmail('&'));
        ensure!(!email.contains(&CHARACTER_EQUALS_SIGN), OracleError::DisallowedCharacterInEmail('='));

        // Mutably borrow from an inmutable RefCell
        let mut id = self.latest_id.borrow_mut();

        // Generate postfix and increment counter
        let postfix = Bytes::from(format!("&uid={}&role=user", id));
        *id += 1;

        // Build a profile by embedding the email into a URL-encoded string
        let profile = dbg!(&self.prefix + &email + &postfix);

        // Encrypt
        let ciphertext = aes::ecb::encrypt(&profile, &self.key);

        Ok(ciphertext)
    }
}
