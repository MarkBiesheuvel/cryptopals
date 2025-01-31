//! Advanced Encryption Standard (AES)
//!
//! ## Examples
//! ```
//! use cryptopals::{aes, byte::*};
//!
//! let key = aes::Block::from(*b"YELLOW SUBMARINE");
//! let ecb_plaintext = ByteSlice::from("cryptopals");
//! let cbc_plaintext = ByteSlice::from("cryptopals");
//!
//! // Since the plaintext is less than 16 bytes (one AES block),
//! // there is no difference between ECB and CBC mode
//! assert_eq!(aes::ecb::encrypt(ecb_plaintext, key.clone()), aes::cbc::encrypt(cbc_plaintext, key.clone()));
//! ```
pub use block::{Block, BLOCK_LENGTH};
pub use roundkey::Roundkey;

mod block;
mod byte_operator;
pub mod cbc;
pub mod ecb;
mod roundkey;

/// The block cipher mode of operation of AES
#[derive(Debug, PartialEq, Eq)]
pub enum BlockMode {
    /// Electronic codebook (ECB) mode
    Ecb,
    /// Cipher block chaining (CBC) mode
    Cbc,
}
