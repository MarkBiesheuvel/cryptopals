//! AES encryption using electronic codebook (ECB) mode
//!
//! ## Examples
//! ```
//! # use cryptopals::{aes, Bytes};
//! #
//! let key = aes::Block::new(*b"YELLOW SUBMARINE");
//! let plaintext = Bytes::from("https://cryptopals.com/");
//!
//! let expected = Bytes::from([
//!     147, 213, 116, 241, 131, 50, 159, 45, 146, 150, 13, 146, 29, 242, 88, 90, 241, 7, 54,
//!     252, 105, 236, 53, 191, 228, 209, 130, 115, 21, 173, 254, 95,
//! ]);
//!
//! assert_eq!(aes::ecb::encrypt(&plaintext, &key), expected);
//! ```
use super::{Block, Roundkey, BLOCK_LENGTH};
use crate::Bytes;

/// AES encrypt using electronic codebook (ECB) mode

pub fn encrypt(plaintext: &Bytes, key: &Block) -> Bytes {
    // Pad the plaintext
    let plaintext = plaintext.pad(BLOCK_LENGTH);

    // Clone the key
    let key = key.clone();

    // Expand the key into 11 roundkeys once
    let roundkeys = Roundkey::from(key).collect::<Vec<_>>();

    // Split the plaintext up into blocks of 16 bytes
    let mut blocks = plaintext
        .blocks(BLOCK_LENGTH)
        .map(|bytes| Block::try_from(&bytes).unwrap())
        .collect::<Vec<_>>();

    // Encrypt each block
    for block in blocks.iter_mut() {
        block.encrypt(&roundkeys);
    }

    // Combine all blocks into a single vector of bytes
    let bytes = blocks.into_iter().fold(Vec::new(), |mut acc, block| {
        acc.append(&mut block.into());
        acc
    });

    Bytes::from(bytes)
}
