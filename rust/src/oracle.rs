//! Collection of Oracles which encrypt data and behave like a black box.
//!
//! Each Oracle has unique characteristics which can be exploited by an
//! adversary.
pub use random_block_mode::RandomBlockMode;
mod random_block_mode;
