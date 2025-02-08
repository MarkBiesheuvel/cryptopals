use super::{find_ecb_postfix_length, AdversaryError};
use crate::{byte::*, aes, oracle::Oracle};
use error_stack::Result;

// A hypothetical domain name we control, so we can create the email addresses which have been used in the ciphertexts
const EMAIL_DOMAIN_NAME: &str = "example.com";

// The offset (in the string) at which to find the first character of an email address
const EMAIL_OFFSET: usize = "email=".len();

// The length (in the string) of the default role
const DEFAULT_ROLE_NAME_LENGTH: usize = "user".len();

// The desired role
const ADMIN_ROLE_NAME: &str = "admin";

/// # Forge an admin profile
/// To do so, we let the oracle generate two valid ciphertexts and
/// we cut and paste them together to forge a new valid ciphertext.
///
/// ## Assumptions
/// We can only control the email field in the user profile, but want to override the role field.
/// The role field is last in the list.
///
/// ## First ciphertext
/// We create an email address with a specific length such that the value of the role starts in a new block.
/// The last two blocks we want would look something like this (where X, Y some variable and Z is padding)
/// ```text
/// [XXX&uid=YY&role=] [userZZZZZZZZZZZZ]
/// ```
///
/// ## Second ciphertext
/// We construct an email address that includes this sequence of bytes and pad it such that it aligns with a block.
/// That would look something like this (where A and Y are some variable and both Z and B are valid padding):
/// ```text
/// [email=AAAAAAAAAA] [adminZZZZZZZZZZZ] [@example.com&uid] [=YYBBBBBBBBBBBBB]
/// ```
///
/// ## Conclusion
/// We cut the block with the word admin from the second ciphertext and
/// paste it over the last block of the first ciphertext.
pub fn forge_admin_profile<O: Oracle>(oracle: &O) -> Result<ByteSlice<'static>, AdversaryError> {
    let block_length = aes::BLOCK_LENGTH;
    let postfix_length = find_ecb_postfix_length(oracle)?;

    // Add valid padding to the desired admin role, so it can be used as if it were the last block
    let mut plaintext = ByteSlice::from(ADMIN_ROLE_NAME);
    plaintext.pad(block_length);

    Ok(ByteSlice::from(""))
}

