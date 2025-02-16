use cryptopals::{
    adversary, aes,
    byte::*,
    oracle::{self, EcbFixedPostfixOracle, Oracle},
};
// Test support
use support::{from_base64, funky_music, TestFile};
mod support;

#[test]
fn challenge_9() {
    let mut input = ByteSlice::from("YELLOW SUBMARINE");
    let expected = ByteSlice::from("YELLOW SUBMARINE\x04\x04\x04\x04");

    // Pad in-place
    input.pad(20);

    assert_eq!(input, expected);
}

#[test]
fn challenge_10() {
    // Input
    let key = aes::Key::from(*b"YELLOW SUBMARINE");
    let plaintext = funky_music();

    let ciphertext = from_base64(TestFile::new("../../data/10.txt").to_string());

    // Verify both encrypt and decrypt
    assert_eq!(aes::cbc::encrypt(plaintext.clone(), &key), ciphertext);
    assert_eq!(aes::cbc::decrypt(ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn challenge_11() {
    // Re-run the test multiple times, since the oracle involves randomness
    for _ in 0..16 {
        let oracle = oracle::RandomBlockModeOracle::default();

        // Let the adversary attack the oracle
        let detected_mode = adversary::detect_aes_block_mode(&oracle).expect("adversary should be successful");

        assert_eq!(&detected_mode, oracle.block_mode());
    }
}

#[test]
fn challenge_12() {
    let oracle = oracle::EcbFixedPostfixOracle::default();

    // It is known that the oracle uses ECB, but verify anyway.
    let detected_mode = adversary::detect_aes_block_mode(&oracle).expect("adversary should be successful");
    assert_eq!(&detected_mode, &aes::BlockMode::Ecb);

    // Let the adversary attack the oracle
    let fixed_postfix = adversary::attack_ecb_fixed_postfix(&oracle).expect("adversary should be successful");

    assert_eq!(&fixed_postfix, oracle.postfix());
}

#[test]
fn challenge_13() {
    let oracle = oracle::UserProfileOracle::default();

    // It is known that the oracle uses ECB, but verify anyway.
    let detected_mode = adversary::detect_aes_block_mode(&oracle).expect("adversary should be successful");
    assert_eq!(&detected_mode, &aes::BlockMode::Ecb);

    // Valid email address should work
    let email = ByteSlice::from("foo@bar.com");
    let result = oracle.encrypt(email);
    assert!(result.is_ok());

    // Should be able to decrypt ciphertext
    let ciphertext = result.expect("oracle should be able to encrypt");
    let user_profile = oracle.decrypt(ciphertext).unwrap();
    assert_eq!(user_profile.is_admin(), false);

    // Invalid email should give an error
    let email = ByteSlice::from("foo@bar.com&role=admin");
    let result = oracle.encrypt(email);
    assert!(result.is_err());

    // Let the adversary forge a ciphertext which gives admin access
    let ciphertext = adversary::forge_admin_profile(&oracle);
    let user_profile = oracle.decrypt(ciphertext).unwrap();
    assert_eq!(user_profile.is_admin(), true);
}

#[test]
fn challenge_14() {
    let oracle = EcbFixedPostfixOracle::with_random_prefix();

    // It is known that the oracle uses ECB, but verify anyway.
    let detected_mode = adversary::detect_aes_block_mode(&oracle).expect("adversary should be successful");
    assert_eq!(&detected_mode, &aes::BlockMode::Ecb);

    // Let the adversary attack the oracle
    let fixed_postfix = adversary::attack_ecb_fixed_postfix(&oracle).expect("adversary should be successful");

    assert_eq!(&fixed_postfix, oracle.postfix());
}

#[test]
fn challenge_15() {
    // Verify valid padding
    let mut valid_padding = ByteSlice::from("ICE ICE BABY\x04\x04\x04\x04");
    let expected = ByteSlice::from("ICE ICE BABY");
    let result = valid_padding.unpad();

    assert!(result.is_ok());
    assert_eq!(valid_padding, expected);

    // Invalid pad value
    let mut invalid_padding = ByteSlice::from("ICE ICE BABY\x17");
    let result = invalid_padding.unpad();

    assert!(result.is_err());

    // Unequal padding
    let mut unequal_padding = ByteSlice::from("ICE ICE BABY\x01\x02\x03\x04");
    let result = unequal_padding.unpad();

    assert!(result.is_err());
}
