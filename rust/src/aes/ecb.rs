//! AES encryption using electronic codebook (ECB) mode
use super::{Block, Roundkey, BLOCK_LENGTH};
use crate::Bytes;

/// AES encrypt using electronic codebook (ECB) mode
pub fn encrypt(plaintext: &Bytes, key: &Bytes) -> Bytes {
    // Expand the key into 11 roundkeys once
    let roundkeys = Roundkey::from(key).collect::<Vec<_>>();

    // Split the plaintext up into blocks of 16 bytes
    let mut blocks = plaintext
        .blocks(BLOCK_LENGTH)
        .map(|bytes| Block::from(&bytes))
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
