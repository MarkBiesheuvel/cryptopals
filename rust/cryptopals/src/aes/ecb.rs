//! AES encryption using electronic codebook (ECB) mode
//!
//! ## Examples
//! ```
//! use cryptopals::{aes, byte::*};
//!
//! let key = aes::Key::from(*b"YELLOW SUBMARINE");
//! let plaintext = ByteSlice::from("https://cryptopals.com/");
//!
//! let expected = ByteSlice::from(&[
//!     147, 213, 116, 241, 131, 50, 159, 45, 146, 150, 13, 146, 29, 242, 88, 90, 241, 7, 54,
//!     252, 105, 236, 53, 191, 228, 209, 130, 115, 21, 173, 254, 95,
//! ][..]);
//!
//! assert_eq!(aes::ecb::encrypt(plaintext, &key), expected);
//! ```
use super::{Block, Key};
use crate::byte::*;

/// AES encrypt using electronic codebook (ECB) mode
///
/// While this implementation does not necessarily consume `plaintext`,
/// however after encrypting a plaintext it makes sense that the plaintext is no longer available
pub fn encrypt(plaintext: ByteSlice, key: &Key) -> ByteSlice<'static> {
    let bytes = plaintext
        // Split into statically sized chunks
        .blocks()
        // Encrypt each block
        .map(|byte_array| {
            let mut block = Block::from(byte_array);
            block.encrypt(key);
            block
        })
        // Collect each byte of each block
        .flat_map(|block| block.unpack().into_iter());

    ByteSlice::from_iter(bytes)
}
