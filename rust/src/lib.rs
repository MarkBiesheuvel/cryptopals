#![doc = include_str!("../README.md")]
#![feature(iter_array_chunks)]
#![warn(missing_docs)]

pub use base64::Base64;
pub use block_iterator::BlockIterator;
pub use bytes::Bytes;
pub use error::CryptopalsError;
pub use hexadecimal::Hexadecimal;

pub mod adversary;
mod base64;
mod block_iterator;
mod bytes;
mod error;
mod hexadecimal;
