#![doc = include_str!("../../README.md")]
#![warn(missing_docs)]
#![allow(unstable_name_collisions)]

pub use bytes::Bytes;
pub use error::CryptopalsError;
pub use ordered_box::OrderedBox;

pub mod adversary;
pub mod aes;
mod bytes;
mod error;
pub mod encoding;
pub mod oracle;
mod ordered_box;
