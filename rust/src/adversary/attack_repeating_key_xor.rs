use super::{attack_single_byte_xor, detect_block_size_repeating_key};
use crate::Bytes;

/// Adversary which takes a ciphertext which has been encrypted using a single
/// byte XOR and tries to reverse it
pub fn attack_repeating_key_xor(ciphertext: &Bytes) -> Option<Bytes> {
    // Get length
    let length = ciphertext.length();

    // Detect block size
    let block_size = detect_block_size_repeating_key(ciphertext).unwrap();

    // Split cipher up into chunks where each chunk `N` contains the `N`th byte of
    // every block
    let chunks = (0..block_size)
        .map(|chunk_number| {
            // Get all bytes for a chunk
            let bytes = (chunk_number..length)
                .step_by(block_size)
                .map(|i| {
                    // Get each byte at position `offset % block_size == chunk_number`
                    assert_eq!(i % block_size, chunk_number);

                    // Get the number at specified index
                    ciphertext.get(i).expect("index should be in bounds")
                })
                .collect::<Vec<_>>();

            // Create new Bytes struct
            Bytes::from(bytes)
        })
        .map(|chunk| {
            // Attack each chunk as a single byte XOR cipher
            attack_single_byte_xor(&chunk).unwrap()
        })
        .collect::<Vec<_>>();

    // Reconstruct the plaintext by placing all bytes back into the original order
    let bytes = (0..length)
        .map(|i| {
            // Modulo/remainder
            let chunk_number = i % block_size;
            // Integer division
            let offset = i / block_size;

            chunks.get(chunk_number).unwrap().get(offset).unwrap()
        })
        .collect::<Vec<_>>();

    // Create new Bytes struct
    Some(Bytes::from(bytes))
}
