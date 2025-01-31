use error_stack::Result;

use super::{find_english_text, AdversaryError};
use crate::byte::*;

/// Adversary which takes a ciphertext which has been encrypted using a single
/// byte XOR and tries to reverse it
pub fn attack_single_byte_xor(ciphertext: &ByteSlice) -> Result<ByteSlice<'static>, AdversaryError> {
    // Try every possible byte as a potential key
    let candidates = (0..=255)
        .map(|key| ciphertext.single_byte_xor(key))
        .collect::<Vec<_>>();

    // Use other adversary to detect the most likely English text
    find_english_text(candidates)
}
