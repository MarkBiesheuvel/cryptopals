use error_stack::Result;
use rand::Rng;

use super::{Oracle, OracleError};
use crate::{aes, byte::*};

/// An oracle which will encrypt a plaintext with a random AES block cipher mode
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
pub struct RandomBlockModeOracle {
    key: aes::Key,
    mode: aes::BlockMode,
    prefix: ByteSlice<'static>,
    postfix: ByteSlice<'static>,
}

impl RandomBlockModeOracle {
    /// Return the randomly selected block mode, so it can be verified by the
    /// test case.
    pub fn block_mode(&self) -> &aes::BlockMode {
        &self.mode
    }
}

impl Default for RandomBlockModeOracle {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Generate a random key
        let key = aes::Key::with_random_values(&mut rng);

        // Generate a random bool in order to pick between the two block modes
        let mode = match rng.gen() {
            true => aes::BlockMode::Ecb,
            false => aes::BlockMode::Cbc,
        };

        // Generate a random length
        let prefix_length = rng.gen_range(5..=10);
        let postfix_length = rng.gen_range(5..=10);

        // Generate random bytes
        let prefix = ByteSlice::with_random_values_and_length(prefix_length, &mut rng);
        let postfix = ByteSlice::with_random_values_and_length(postfix_length, &mut rng);

        RandomBlockModeOracle {
            key,
            mode,
            prefix,
            postfix,
        }
    }
}

impl Oracle for RandomBlockModeOracle {
    fn encrypt(&self, plaintext: ByteSlice<'_>) -> Result<ByteSlice<'static>, OracleError> {
        // Build a payload by adding the prefix and postfix to the plaintext
        let payload = &self.prefix + plaintext + &self.postfix;

        // Encrypt using the selected mode
        let ciphertext = match self.mode {
            aes::BlockMode::Ecb => aes::ecb::encrypt(payload, &self.key),
            aes::BlockMode::Cbc => aes::cbc::encrypt(payload, &self.key),
        };

        Ok(ciphertext)
    }
}
