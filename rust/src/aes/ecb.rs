//! AES encryption using electronic codebook (ECB) mode
use super::{Block, Roundkey, BLOCK_LENGTH};
use crate::{Bytes, CryptopalsError};

/// AES encrypt using electronic codebook (ECB) mode
pub fn encrypt(plaintext: &Bytes, key: &Bytes) -> Result<Bytes, CryptopalsError> {
    // TODO: pad the plaintext first

    // Expand the key into 11 roundkeys once
    let roundkeys = Roundkey::try_from(key)?.collect::<Vec<_>>();

    // Split the plaintext up into "blocks" of 16 bytes
    // TODO: reimplement Bytes.block_iterator to return references instead
    let bytes = plaintext
        .blocks(BLOCK_LENGTH)
        .map(|mut bytes| {
            // Padding
            if bytes.length() < BLOCK_LENGTH {
                bytes.pad(BLOCK_LENGTH);
            }

            // Load the "block" into the Block struct
            let mut block = Block::try_from(&bytes)?;

            // Encrypt the block
            block.encrypt(&roundkeys);

            // Return
            Ok(block)
        })
        .collect::<Result<Vec<_>, CryptopalsError>>()?
        .into_iter()
        .fold(Vec::new(), |mut acc, block| {
            acc.append(&mut block.into());
            acc
        });

    Ok(Bytes::from(bytes))
}
