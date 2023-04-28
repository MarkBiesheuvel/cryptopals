#![feature(iter_array_chunks)]
//! the cryptopals crypto challenges

pub use base64::Base64;
pub use bytes::Bytes;
pub use error::CryptopalsError;
pub use hexadecimal::Hexadecimal;

pub mod adversary;
mod base64;
mod bytes;
mod error;
mod hexadecimal;
