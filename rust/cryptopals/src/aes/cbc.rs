//! AES encryption using cipher block chaining (CBC) mode
//!
//! ## Examples
//! ```
//! # use cryptopals::{aes, Bytes};
//! #
//! let key = aes::Block::from("YELLOW SUBMARINE");
//! let plaintext = Bytes::from("https://cryptopals.com/");
//!
//! let expected = Bytes::from([
//!     147, 213, 116, 241, 131, 50, 159, 45, 146, 150, 13, 146, 29, 242, 88, 90, 232, 196,
//!     246, 36, 93, 32, 2, 180, 64, 12, 116, 236, 193, 5, 120, 27,
//! ]);
//!
//! assert_eq!(aes::cbc::encrypt(&plaintext, &key), expected);
//! ```
use super::{Block, Roundkey, BLOCK_LENGTH};
use crate::Bytes;

/// AES encrypt using cipher block chaining (CBC) mode
pub fn encrypt(plaintext: &Bytes, key: &Block) -> Bytes {
    // Clone the key
    let key = key.clone();

    // Expand the key into 11 roundkeys once
    let roundkeys = Roundkey::from(key).collect::<Vec<_>>();

    // Initialization vector
    let mut iv = Block::default();

    // Split the plaintext up into blocks of 16 bytes
    let mut blocks = plaintext
        .blocks(BLOCK_LENGTH)
        .map(|bytes| Block::from(&bytes))
        .collect::<Vec<_>>();

    // Encrypt each block
    for block in blocks.iter_mut() {
        // Apply IV from previous round
        *block ^= &iv;

        // Encrypt block
        block.encrypt(&roundkeys);

        // Create a copy of the current block in order to use it for the next round
        iv = block.clone();
    }

    // Combine all blocks into a single vector of bytes
    let bytes = blocks.into_iter().fold(Vec::new(), |mut acc, block| {
        acc.append(&mut block.into());
        acc
    });

    Bytes::from(bytes)
}
