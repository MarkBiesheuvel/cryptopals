use super::{Oracle, OracleError};
use crate::{aes, byte::*};
use error_stack::{bail, ensure, IntoReport, Result, ResultExt};
use std::cell::RefCell;

// Special characters for URL-encoding
const CHARACTER_AMPERSAND: char = '&';
const CHARACTER_EQUALS_SIGN: char = '=';
const BYTE_AMPERSAND: u8 = CHARACTER_AMPERSAND as u8;
const BYTE_EQUALS_SIGN: u8 = CHARACTER_EQUALS_SIGN as u8;

/// An oracle which takes a plaintext email address and creates an encrypted
/// token for it.
///
/// During creation it will:
///  - randomly generate an encryption key
pub struct UserProfileOracle {
    key: aes::Key,
    prefix: ByteSlice<'static>,
    latest_id: RefCell<usize>,
}

/// Role of a user profile
#[derive(Debug, PartialEq)]
pub enum UserRole {
    /// A regular user with no special permissions
    User,
    /// An admin user with additional permissions
    Admin,
}

/// A valid user. The result of decrypting the ciphertext of the Oracle
#[derive(Debug)]
pub struct UserProfile {
    email: String,
    id: usize,
    role: UserRole,
}

impl Default for UserProfileOracle {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        // Generate a random key
        let key = aes::Key::with_random_values(&mut rng);

        // Prefix will always be the same, so we can already make a Bytes struct
        let prefix = ByteSlice::from("email=");

        // Auto increment the UUID of the user, but start with a number that won't
        // likely impact the padding of the ciphertext
        let latest_id = RefCell::new(1_000);

        UserProfileOracle {
            key,
            prefix,
            latest_id,
        }
    }
}

impl Oracle for UserProfileOracle {
    fn encrypt(&self, email: ByteSlice<'_>) -> Result<ByteSlice<'static>, OracleError> {
        // Input validation
        ensure!(!email.contains(&BYTE_AMPERSAND), OracleError::DisallowedCharacterInEmail(CHARACTER_AMPERSAND));
        ensure!(
            !email.contains(&BYTE_EQUALS_SIGN),
            OracleError::DisallowedCharacterInEmail(CHARACTER_EQUALS_SIGN)
        );

        // Mutably borrow from an immutable RefCell
        let mut id = self.latest_id.borrow_mut();

        // Generate postfix and increment counter
        let postfix = ByteSlice::from(format!("&uid={}&role=user", id));
        *id += 1;

        // Build a profile by embedding the email into a URL-encoded string
        let profile = &self.prefix + email + postfix;

        // Encrypt
        let ciphertext = aes::ecb::encrypt(profile, &self.key);

        Ok(ciphertext)
    }
}

impl UserProfileOracle {
    /// Decrypt a ciphertext that was encrypted by this oracle.
    /// The resulting plaintext will be parsed and returned as UserProfile
    pub fn decrypt(&self, ciphertext: ByteSlice<'_>) -> Result<UserProfile, OracleError> {
        // Decrypt using ECB mode and same key
        let plaintext = aes::ecb::decrypt(ciphertext, &self.key).change_context(OracleError::InvalidCiphertext)?;

        // Convert from bytes to string
        let plaintext = dbg!(plaintext.to_string());

        // Uninitialized value
        let mut id = None;
        let mut email = None;
        let mut role = None;

        // Loop over each variable assignment and capture it's value
        for assignment in plaintext.split(CHARACTER_AMPERSAND) {
            let (key, value) = assignment
                .split_once(CHARACTER_EQUALS_SIGN)
                .ok_or(OracleError::InvalidKeyValueString)?;

            match key {
                "uid" => {
                    // Parse and store ID
                    let value = value
                        .parse::<usize>()
                        .into_report()
                        .change_context(OracleError::InvalidId)?;

                    id = Some(value);
                }
                "email" => {
                    // Take ownership and tore email
                    let value = value.to_owned();
                    email = Some(value);
                }
                "role" => {
                    // Parse and store role
                    let value = match value {
                        "user" => UserRole::User,
                        "admin" => UserRole::Admin,
                        _unknown_role => {
                            bail!(OracleError::InvalidRole);
                        }
                    };

                    role = Some(value);
                }
                _unknown_field => {
                    bail!(OracleError::UnexpectedField);
                }
            }
        }

        let id = id.ok_or(OracleError::MissingField("uid"))?;
        let email = email.ok_or(OracleError::MissingField("email"))?;
        let role = role.ok_or(OracleError::MissingField("role"))?;

        Ok(UserProfile { id, email, role })
    }
}

impl UserProfile {
    /// ID of user
    pub fn id(&self) -> usize {
        self.id
    }

    // Email address of user
    pub fn email(&self) -> &str {
        &self.email
    }

    // Whether a user is admin
    pub fn is_admin(&self) -> bool {
        self.role == UserRole::Admin
    }
}
