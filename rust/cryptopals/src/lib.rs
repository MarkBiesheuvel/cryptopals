#![doc = include_str!("../../README.md")]
#![warn(missing_docs)]
#![allow(unstable_name_collisions)]

pub use error::CryptopalsError;

pub mod adversary;
pub mod aes;
pub mod byte;
pub mod encoding;
mod error;
pub mod oracle;
