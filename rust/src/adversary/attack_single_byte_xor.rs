use super::detect_english_text;
use crate::Bytes;

/// Adversary which takes a ciphertext which has been encrypted using a single
/// byte XOR and tries to reverse it
pub fn attack_single_byte_xor(ciphertext: Bytes) -> Option<Bytes> {
    // Try every possible byte as a potential key
    let candidates = (0..=255)
        .map(|key| ciphertext.single_byte_xor(key))
        .collect::<Vec<_>>();

    // Use other adversary to detect the most likely English text
    detect_english_text(candidates)
}
