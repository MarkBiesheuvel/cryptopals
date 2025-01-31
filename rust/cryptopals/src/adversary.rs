//! Collection of adversaries that can be used to break encryption or detect
//! hidden properties

pub use attack_ecb_fixed_postfix::attack_ecb_fixed_postfix;
pub use attack_repeating_key_xor::attack_repeating_key_xor;
pub use attack_single_byte_xor::attack_single_byte_xor;
pub use average_hamming_distance::average_hamming_distance;
pub use detect_aes_block_mode::detect_aes_block_mode;
pub use detect_block_size_repeating_key::detect_block_size_repeating_key;
pub use error::AdversaryError;
pub use find_aes_ecb_ciphertext::find_aes_ecb_ciphertext;
pub use find_english_text::find_english_text;

mod attack_ecb_fixed_postfix;
mod attack_repeating_key_xor;
mod attack_single_byte_xor;
mod average_hamming_distance;
mod detect_aes_block_mode;
mod detect_block_size_repeating_key;
mod error;
mod find_aes_ecb_ciphertext;
mod find_english_text;
