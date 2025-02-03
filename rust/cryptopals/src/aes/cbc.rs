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
use std::ops::BitXorAssign;

/// AES encrypt using cipher block chaining (CBC) mode.
///
/// While this implementation does not necessarily consume `plaintext`,
/// however after encrypting a plaintext it makes sense that the plaintext is no longer available
pub fn encrypt(plaintext: ByteSlice, key: &Key) -> ByteSlice<'static> {
    // Pad with additional characters
    // This also creates an owned copy of plaintext instead of a reference
    let plaintext = plaintext.pad(BLOCK_LENGTH);

    let mut blocks = plaintext
        // Split into statically sized chunks
        .blocks()
        // This should never error
        .expect("plaintext should be padded to correct length")
        // Convert to block
        .map(Block::from)
        // Collect
        .collect::<Vec<_>>();

    // Modify each block in place.
    for index in 0..blocks.len() {
        // Use the split_at_mut function to both get a mutable reference to current block
        // and immutable reference to previous block.
        let (left, right) = blocks.split_at_mut(index);

        // Initialization vector ...
        let iv = match index {
            // ... from all zeroes
            0 => &Block::from(ByteArray::with_repeated_byte(0)),
            // ... from previous round
            _ => left
                .get(index - 1)
                .expect("index - 1 should be within bounds"),
        };

        // Get mutable reference to current block
        let block = right
            .get_mut(index)
            .expect("index - 1 should be within bounds");

        // Apply IV
        block.bitxor_assign(iv);

        // Encrypt
        block.encrypt(key);
    }

    // Collect each byte of each block
    let bytes = blocks.into_iter().flat_map(Block::into_iter);

    ByteSlice::from_iter(bytes)
}
