//! Advanced Encryption Standard (AES)
//!
//! ## Examples
//! ```
//! # use cryptopals::{aes, Bytes};
//! #
//! let key = Bytes::from("YELLOW SUBMARINE");
//! let plaintext = Bytes::from("cryptopals");
//!
//! // Since the plaintext is less than 16 bytes (one AES block),
//! // there is no difference between ECB and CBC mode
//! assert_eq!(aes::ecb::encrypt(&plaintext, &key), aes::cbc::encrypt(&plaintext, &key));
//! ```
pub use block::{Block, BLOCK_LENGTH};
use g_mul::g_mul;
pub use roundkey::Roundkey;
use sub_byte::sub_byte;

mod block;
pub mod cbc;
pub mod ecb;
mod g_mul;
mod roundkey;
mod sub_byte;

/// The block cipher mode of operation of AES
pub enum BlockMode {
    /// Electronic codebook (ECB) mode
    Ecb,
    /// Cipher block chaining (CBC) mode
    Cbc,
}
