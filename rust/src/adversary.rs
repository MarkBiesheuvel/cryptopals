//! Collection of adversaries to break ciphers
pub use attack_single_byte_xor::attack_single_byte_xor;
pub use detect_english_text::detect_english_text;

mod attack_single_byte_xor;
mod detect_english_text;
