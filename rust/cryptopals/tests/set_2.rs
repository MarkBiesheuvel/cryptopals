use cryptopals::{adversary, aes, byte::*, encoding::Base64, oracle, oracle::Oracle};
// Test support
use support::{funky_music, ok, FileLineIterator, TestResult};
mod support;

#[test]
fn challenge_9() -> TestResult {
    let mut input = ByteSlice::from("YELLOW SUBMARINE");
    let expected = ByteSlice::from("YELLOW SUBMARINE\x04\x04\x04\x04");

    // Pad in-place
    input.pad(20);

    assert_eq!(input, expected);

    ok()
}

#[test]
fn challenge_10() -> TestResult {
    // Input
    let key = aes::Key::from(*b"YELLOW SUBMARINE");
    let plaintext = funky_music()?;

    let ciphertext = FileLineIterator::new("../../data/10.txt")?.concat();
    let ciphertext = ByteSlice::try_from(Base64::from(ciphertext))?;

    // Verify both encrypt and decrypt
    assert_eq!(aes::cbc::encrypt(plaintext.clone(), &key), ciphertext);
    assert_eq!(aes::cbc::decrypt(ciphertext, &key)?, plaintext);

    ok()
}

#[test]
fn challenge_11() -> TestResult {
    // Re-run the test multiple times, since the oracle involves randomness
    for _ in 0..16 {
        let oracle = oracle::RandomBlockMode::default();

        // Let the adversary attack the oracle
        let detected_mode = adversary::detect_aes_block_mode(&oracle)?;

        assert_eq!(&detected_mode, oracle.block_mode());
    }

    ok()
}

#[test]
fn challenge_12() -> TestResult {
    let oracle = oracle::EcbFixedPostfix::default();

    // It is known that the oracle uses ECB, but verify anyway.
    let detected_mode = adversary::detect_aes_block_mode(&oracle)?;
    assert_eq!(&detected_mode, &aes::BlockMode::Ecb);

    // Let the adversary attack the oracle
    let fixed_postfix = adversary::attack_ecb_fixed_postfix(&oracle)?;

    assert_eq!(&fixed_postfix, oracle.postfix());

    ok()
}

#[test]
fn challenge_13() -> TestResult {
    let oracle = oracle::UserProfile::default();

    // It is known that the oracle uses ECB, but verify anyway.
    let detected_mode = adversary::detect_aes_block_mode(&oracle)?;
    assert_eq!(&detected_mode, &aes::BlockMode::Ecb);

    // Valid email address should work
    let email = ByteSlice::from("foo@bar.com");
    let result = oracle.encrypt(email);
    assert!(result.is_ok());

    // Invalid email should give an error
    let email = ByteSlice::from("foo@bar.com&role=admin");
    let result = oracle.encrypt(email);
    assert!(result.is_err());

    ok()
}
