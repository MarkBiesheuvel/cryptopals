//! Collection of Oracles which encrypt data and behave like a black box.
//!
//! Each Oracle has unique characteristics which can be exploited by an
//! adversary.
pub use ecb_fixed_postfix::EcbFixedPostfix;
pub use random_block_mode::RandomBlockMode;

use crate::Bytes;

mod ecb_fixed_postfix;
mod random_block_mode;

/// Trait that should be implemented by all oracles.
///
/// This allows adversaries to accept any oracle as input.
///
/// ## Examples
/// ```
/// # use cryptopals::{Oracle, Bytes};
/// #
/// #[derive(Default)]
/// struct SingleByteXor;
///
/// // Implementing the Oracle trait with a simple XOR operation
/// impl Oracle for SingleByteXor {
///     fn encrypt(&self, plaintext: Bytes) -> Bytes {
///         plaintext.single_byte_xor(42)
///     }
/// }
///
/// // Verify that the oracle works as expected
/// let oracle = SingleByteXor::default();
/// let plaintext = Bytes::from("cryptopals");
/// let expected = Bytes::from("IXSZ^EZKFY");
/// assert_eq!(oracle.encrypt(plaintext), expected);
/// ```
pub trait Oracle: Default {
    /// Perform encrypt operation
    fn encrypt(&self, plaintext: Bytes) -> Bytes;
}
