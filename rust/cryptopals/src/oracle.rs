//! Collection of Oracles which encrypt data and behave like a black box.
//!
//! Each Oracle has unique characteristics which can be exploited by an
//! adversary.
pub use ecb_fixed_postfix::EcbFixedPostfix;
pub use error::OracleError;
use error_stack::Result;
pub use random_block_mode::RandomBlockMode;
pub use user_profile::UserProfile;

use crate::Bytes;

mod ecb_fixed_postfix;
mod error;
mod random_block_mode;
mod user_profile;

/// Trait that should be implemented by all oracles.
///
/// This allows adversaries to accept any oracle as input.
///
/// ## Examples
/// ```
/// # use cryptopals::{Bytes, oracle::{Oracle, OracleError}};
/// # use error_stack::Result;
/// #
/// #[derive(Default)]
/// struct SingleByteXor;
///
/// // Implementing the Oracle trait with a simple XOR operation
/// impl Oracle for SingleByteXor {
///     fn encrypt(&self, plaintext: Bytes) -> Result<Bytes, OracleError> {
///         Ok(plaintext.single_byte_xor(42))
///     }
/// }
///
/// // Verify that the oracle works as expected
/// let oracle = SingleByteXor::default();
/// let plaintext = Bytes::from("cryptopals");
///
/// let ciphertext = oracle.encrypt(plaintext)?;
/// let expected = Bytes::from("IXSZ^EZKFY");
/// assert_eq!(ciphertext, expected);
/// #
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub trait Oracle: Default {
    /// Perform encrypt operation
    fn encrypt(&self, plaintext: Bytes) -> Result<Bytes, OracleError>;
}
