use super::find_ecb_postfix_length;
use crate::{aes, byte::*, oracle::Oracle};

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
pub fn forge_admin_profile<O: Oracle>(oracle: &O) -> ByteSlice<'static> {
    // Build the desired last block
    let encrypted_admin_block = get_encrypted_admin_block(oracle);

    // Build ciphertext where the role name starts exactly in the last block
    let ciphertext = get_ciphertext_with_role_in_last_block(oracle);

    // Split into blocks
    let mut blocks = ciphertext
        .blocks()
        .expect("ciphertext should have valid length.")
        .collect::<Vec<_>>();

    // Cut and paste desired block
    blocks.pop();
    blocks.push(encrypted_admin_block);

    // Build new ciphertext from blocks
    let iter = blocks.into_iter().flat_map(|block| block.into_iter());
    ByteSlice::from_iter(iter)
}

fn get_encrypted_admin_block<O: Oracle>(oracle: &O) -> ByteArray<{ aes::BLOCK_LENGTH }> {
    // Add valid padding to the desired admin role, so it can be used as if it were the last block
    let mut plaintext_admin_block = ByteSlice::from(ADMIN_ROLE_NAME);
    plaintext_admin_block.pad(aes::BLOCK_LENGTH);

    // Determine how many characters we need to prefix such that "email=" + our prefix fits in exactly one block
    let prefix_length = aes::BLOCK_LENGTH - EMAIL_OFFSET;
    let prefix = "a".repeat(prefix_length);

    // Construct email address from all the parts
    let email_address = prefix + &plaintext_admin_block.to_string() + EMAIL_DOMAIN_NAME;
    let plaintext = ByteSlice::from(email_address);

    // Let the oracle encrypt
    let ciphertext = oracle
        .encrypt(plaintext)
        .expect("oracle should be able to encrypt plaintext");
    let mut blocks = ciphertext
        .blocks()
        .expect("ciphertext should have valid length.");

    // The second block contains the "admin" string with padding
    blocks
        .nth(1)
        .expect("ciphertext should have at least 2 blocks")
}

fn get_ciphertext_with_role_in_last_block<O: Oracle>(oracle: &O) -> ByteSlice<'static> {
    // Find the number of bytes that are appended after the input that we control
    let postfix_length = find_ecb_postfix_length(oracle).expect("oracle should be able to encrypt plaintext");

    // Calculate how long our email address needs to be in order for it to push the role name into a separate block.
    // ASSUMPTION: 2 blocks is enough to fit the prefix, email domain and the postfix-minus-role.
    let prefix_length = (2 * aes::BLOCK_LENGTH) - EMAIL_DOMAIN_NAME.len() - (postfix_length - DEFAULT_ROLE_NAME_LENGTH);
    let prefix = "a".repeat(prefix_length);

    // Construct email address from all the parts
    let email_address = prefix + EMAIL_DOMAIN_NAME;
    let plaintext = ByteSlice::from(email_address);

    // Let the oracle encrypt
    oracle
        .encrypt(plaintext)
        .expect("oracle should be able to encrypt plaintext")
}
