#![doc = include_str!("../../README.md")]
#![warn(missing_docs)]
#![allow(unstable_name_collisions)]

pub use byte_encoding_macro::{base64, hex};

pub use error::CryptopalsError;

pub mod adversary;
pub mod aes;
pub mod byte;
mod error;
pub mod oracle;
