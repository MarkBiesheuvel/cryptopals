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
pub use roundkey::Roundkey;
use sub_byte::sub_byte;

mod block;
pub mod cbc;
pub mod ecb;
mod roundkey;
mod sub_byte;
