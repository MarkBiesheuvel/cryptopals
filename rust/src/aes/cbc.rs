//! AES encryption using cipher block chaining (CBC) mode
use super::{Block, Roundkey, BLOCK_LENGTH};
use crate::{Bytes, CryptopalsError};

/// AES encrypt using cipher block chaining (CBC) mode
pub fn encrypt(plaintext: &Bytes, key: &Bytes) -> Result<Bytes, CryptopalsError> {
    // Expand the key into 11 roundkeys once
    let roundkeys = Roundkey::try_from(key)?.collect::<Vec<_>>();

    // Initialization vector
    let mut iv = Block::default();

    // Split the plaintext up into blocks of 16 bytes
    let mut blocks = plaintext
        .blocks(BLOCK_LENGTH)
        .map(|mut bytes| {
            // Padding
            if bytes.length() < BLOCK_LENGTH {
                bytes.pad(BLOCK_LENGTH);
            }

            // Load the bytes into a Block struct
            Block::try_from(&bytes)
        })
        .collect::<Result<Vec<_>, CryptopalsError>>()?;

    // Encrypt each block
    for block in blocks.iter_mut() {
        // Apply IV from previous round
        *block ^= &iv;

        // Encrypt block
        block.encrypt(&roundkeys);

        // Create a copy of the current block in order to use it for the next round
        // TODO: figure out if there is a better way
        iv = block.clone();
    }

    // Combine all blocks into a single vector of bytes
    let bytes = blocks.into_iter().fold(Vec::new(), |mut acc, block| {
        acc.append(&mut block.into());
        acc
    });

    Ok(Bytes::from(bytes))
}
