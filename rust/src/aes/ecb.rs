//! AES encryption using electronic codebook (ECB) mode
use std::ops::BitXorAssign;

use super::{Block, Roundkey};
use crate::{Bytes, CryptopalsError};

/// AES encrypt using electronic codebook (ECB) mode
pub fn encrypt(plaintext: &Bytes, key: &Bytes) -> Result<Bytes, CryptopalsError> {
    // TODO: split plaintext up into multiple blocks
    // TODO: pad the plaintext first

    // Load the plaintext into the state
    let mut state = Block::try_from(plaintext)?;

    // Create an iterator over the round keys
    let roundkey_iterator = Roundkey::try_from(key)?;

    for (round_number, round_key) in roundkey_iterator.enumerate() {
        if 0 < round_number {
            // Perform substitution bytes on every round after round 0
            state.sub_bytes();

            // Perform shift rows on every round after round 0
            state.shift_rows();

            if round_number < 10 {
                // Perform mix columns on rounds 1 through 9
                state.mix_columns();
            }
        }

        // Apply round key on every round
        state.bitxor_assign(round_key)
    }

    Ok(Bytes::from(state))
}
