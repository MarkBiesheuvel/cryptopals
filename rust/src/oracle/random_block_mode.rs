use rand::Rng;

use crate::{aes, Bytes};

/// Create a new oracle which will encrypt a plaintext.
///
/// During creation it will:
///  - randomly generate an encryption key
///  - randomly selected block cipher mode; either ECB or CBC
///  - randomly generate a prefix between 5 and 10 bytes
///  - randomly generate a postfix between 5 and 10 bytes
///
/// During encryption it will:
///  - concatenate the prefix, plaintext, and postfix
///  - encrypt everything using the previously selected block mode
pub struct RandomBlockMode {
    key: Bytes,
    mode: aes::BlockMode,
    prefix: Bytes,
    postfix: Bytes,
}

impl Default for RandomBlockMode {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Generate a random key
        let key = Bytes::with_random_values(aes::BLOCK_LENGTH, &mut rng);

        // Generate a random bool in order to pick between the two block modes
        let mode = match rng.gen() {
            true => aes::BlockMode::Ecb,
            false => aes::BlockMode::Cbc,
        };

        // Generate a random length
        let prefix_length = rng.gen_range(5..=10);
        let postfix_length = rng.gen_range(5..=10);

        // Generate random bytes
        let prefix = Bytes::with_random_values(prefix_length, &mut rng);
        let postfix = Bytes::with_random_values(postfix_length, &mut rng);

        RandomBlockMode {
            key,
            mode,
            prefix,
            postfix,
        }
    }
}

impl RandomBlockMode {
    /// Perform encrypt operation
    pub fn encrypt(&self, plaintext: Bytes) -> Bytes {
        // Convert everything to iterators
        let prefix = self.prefix.iter();
        let plaintext = plaintext.iter();
        let postfix = self.postfix.iter();

        // Build a payload by chaining all the iterators and copy all the bytes
        let payload = Bytes::from_iter(prefix.chain(plaintext).chain(postfix).copied());

        // Encrypt using the selected mode
        match self.mode {
            aes::BlockMode::Ecb => aes::ecb::encrypt(&payload, &self.key),
            aes::BlockMode::Cbc => aes::cbc::encrypt(&payload, &self.key),
        }
    }
}
