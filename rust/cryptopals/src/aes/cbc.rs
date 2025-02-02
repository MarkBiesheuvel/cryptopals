//! AES encryption using cipher block chaining (CBC) mode
//!
//! ## Examples
//! ```
//! use cryptopals::{aes, byte::*};
//!
//! let key = aes::Key::from(*b"YELLOW SUBMARINE");
//! let plaintext = ByteSlice::from("https://cryptopals.com/");
//!
//! let expected = ByteSlice::from([
//!     147, 213, 116, 241, 131, 50, 159, 45, 146, 150, 13, 146, 29, 242, 88, 90, 232, 196,
//!     246, 36, 93, 32, 2, 180, 64, 12, 116, 236, 193, 5, 120, 27,
//! ].as_ref());
//!
//! assert_eq!(aes::cbc::encrypt(plaintext, &key), expected);
//! ```
use super::{Block, Key, BLOCK_LENGTH};
use crate::byte::*;

/// AES encrypt using cipher block chaining (CBC) mode.
///
/// While this implementation does not necessarily consume `plaintext`,
/// however after encrypting a plaintext it makes sense that the plaintext is no longer available
pub fn encrypt(plaintext: ByteSlice, key: &Key) -> ByteSlice<'static> {
    // Pad with additional characters
    // This also creates an owned copy of plaintext instead of a reference
    let plaintext = plaintext.pad(BLOCK_LENGTH);

    // Initialization vector
    let mut iv = Block::from(ByteArray::with_repeated_byte(0));

    let bytes = plaintext
        // Split into statically sized chunks
        .blocks()
        // TODO: propagate error?
        .unwrap()
        // Encrypt each block
        .map(|byte_array| {
            let mut block = Block::from(byte_array);

            // Apply IV from previous round
            block ^= &iv;

            block.encrypt(key);

            // Create a copy of the current block in order to use it for the next round
            iv = block.clone();

            block
        })
        // Collect each byte of each block
        .flat_map(|block| block.into_iter());

    ByteSlice::from_iter(bytes)
}
