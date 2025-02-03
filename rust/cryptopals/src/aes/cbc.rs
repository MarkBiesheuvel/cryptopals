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
use crate::{byte::*, CryptopalsError};
use error_stack::Result;
use std::ops::BitXorAssign;

/// AES encrypt using cipher block chaining (CBC) mode.
pub fn encrypt(mut plaintext: ByteSlice, key: &Key) -> ByteSlice<'static> {
    // Pad with additional characters
    plaintext.pad(BLOCK_LENGTH);

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
                .expect("[index-1] should be within bounds"),
        };

        // Get mutable reference to current block
        // Since this is the right-side from the split, index is 0
        let block = right.get_mut(0).expect("index should be within bounds");

        // Apply IV
        block.bitxor_assign(iv);

        // Encrypt
        block.encrypt(key);
    }

    // Collect each byte of each block
    let bytes = blocks.into_iter().flat_map(Block::into_iter);

    ByteSlice::from_iter(bytes)
}

/// AES decrypt using cipher block chaining (CBC) mode.
pub fn decrypt(ciphertext: ByteSlice, key: &Key) -> Result<ByteSlice<'static>, CryptopalsError> {
    let mut blocks = ciphertext
        // Split into statically sized chunks
        .blocks()?
        // Convert to block
        .map(Block::from)
        // Collect
        .collect::<Vec<_>>();

    // Modify each block in place.
    for index in (0..blocks.len()).rev() {
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
                .expect("[index-1] should be within bounds"),
        };

        // Get mutable reference to current block
        // Since this is the right-side from the split, index is 0
        let block = right.get_mut(0).expect("index should be within bounds");

        // /Decrypt
        block.decrypt(key);

        // Undo IV
        block.bitxor_assign(iv);
    }

    // Construct plaintext
    let bytes = blocks.into_iter().flat_map(Block::into_iter);
    let mut plaintext = ByteSlice::from_iter(bytes);

    // Remove padding
    plaintext.unpad()?;

    Ok(plaintext)
}
