//! Collection of adversaries to break ciphers
pub use attack_repeating_key_xor::attack_repeating_key_xor;
pub use attack_single_byte_xor::attack_single_byte_xor;
pub use average_hamming_distance::average_hamming_distance;
pub use detect_block_size_repeating_key::detect_block_size_repeating_key;
pub use detect_english_text::detect_english_text;

mod attack_repeating_key_xor;
mod attack_single_byte_xor;
mod average_hamming_distance;
mod detect_block_size_repeating_key;
mod detect_english_text;
