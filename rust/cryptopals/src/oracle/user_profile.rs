use std::cell::RefCell;

use super::Oracle;
use crate::{aes, Bytes};

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
    fn encrypt(&self, email: Bytes) -> Bytes {
        // Mutably borrow from an inmutable RefCell
        let mut id = self.latest_id.borrow_mut();

        // Generate postfix and increment counter
        let postfix = Bytes::from(format!("&uid={}&role=user", id));
        *id += 1;

        // Build a profile by embedding the email into a URL-encoded string
        let profile = dbg!(&self.prefix + &email + &postfix);

        // Encrypt
        aes::ecb::encrypt(&profile, &self.key)
    }
}
