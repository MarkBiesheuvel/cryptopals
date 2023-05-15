//! AES encryption using electronic codebook (ECB) mode
use super::{Block, Roundkey, BLOCK_LENGTH};
use crate::{Bytes, CryptopalsError};

/// AES encrypt using electronic codebook (ECB) mode
pub fn encrypt(plaintext: &Bytes, key: &Bytes) -> Result<Bytes, CryptopalsError> {
    // Expand the key into 11 roundkeys once
    let roundkeys = Roundkey::try_from(key)?.collect::<Vec<_>>();

    // Split the plaintext up into "blocks" of 16 bytes
    let bytes = plaintext
        .slices(BLOCK_LENGTH)
        .map(|slice| {
            // Load the slice into the Block struct
            let mut block = Block::with_padding(slice);

            // Encrypt the block
            block.encrypt(&roundkeys);

            // Return
            block
        })
        .fold(Vec::new(), |mut acc, block| {
            acc.append(&mut block.into());
            acc
        });

    Ok(Bytes::from(bytes))
}
