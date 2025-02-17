//! Collection of adversaries that can be used to break encryption or detect
//! hidden properties

pub use attack_ecb_fixed_postfix::attack_ecb_fixed_postfix;
pub use attack_repeating_key_xor::attack_repeating_key_xor;
pub use attack_single_byte_xor::attack_single_byte_xor;
pub use average_hamming_distance::average_hamming_distance;
pub use detect_aes_block_mode::detect_aes_block_mode;
pub use detect_aes_properties::{detect_aes_properties, AesEcbProperties};
pub use detect_block_size_repeating_key::detect_block_size_repeating_key;
pub use error::AdversaryError;
pub use find_aes_ecb_ciphertext::find_aes_ecb_ciphertext;
pub use find_ecb_postfix_length::find_ecb_postfix_length;
pub use find_english_text::find_english_text;
pub use forge_admin_profile::forge_admin_profile;
use get_ciphertext_length::get_ciphertext_length;
pub use scored_item::ScoredItem;

mod attack_ecb_fixed_postfix;
mod attack_repeating_key_xor;
mod attack_single_byte_xor;
mod average_hamming_distance;
mod detect_aes_block_mode;
mod detect_aes_properties;
mod detect_block_size_repeating_key;
mod error;
mod find_aes_ecb_ciphertext;
mod find_ecb_postfix_length;
mod find_english_text;
mod forge_admin_profile;
mod get_ciphertext_length;
mod scored_item;

// An arbitrary character to use when building a plaintext of a given length.
// Using a NULL byte (0x00) might be raise suspicion in an oracle, so let's use an alphanumeric character instead
// I choose the byte "U" as it's binary representation has alternating ones and zeroes, i.e. 0101 0101
const DEFAULT_BYTE: u8 = b'U';
