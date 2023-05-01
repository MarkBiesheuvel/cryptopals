//! Collection of adversaries to break ciphers
pub use attack_single_byte_xor::attack_single_byte_xor;
pub use average_hamming_distance::average_hamming_distance;
pub use detect_block_size::detect_block_size;
pub use detect_english_text::detect_english_text;

mod attack_single_byte_xor;
mod average_hamming_distance;
mod detect_block_size;
mod detect_english_text;
