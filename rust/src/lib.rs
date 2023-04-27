#![feature(iter_array_chunks)]

pub use bytes::Bytes;
pub use error::CryptopalsError;

mod bytes;
mod error;
mod functions;
