#![doc = include_str!("../README.md")]
#![feature(iter_array_chunks)]
#![warn(missing_docs)]

pub use base64::Base64;
pub use bytes::Bytes;
pub use error::CryptopalsError;
pub use hexadecimal::Hexadecimal;
use scored_box::ScoredBox;

pub mod adversary;
pub mod aes;
mod base64;
mod bytes;
mod error;
mod hexadecimal;
mod scored_box;
