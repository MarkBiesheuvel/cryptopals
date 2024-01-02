use cryptopals::{adversary, aes, oracle, Bytes};
// Test support
use support::{funky_music, ok, FileLineIterator, TestResult};
mod support;

#[test]
fn challenge_9() -> TestResult {
    let input = Bytes::from("YELLOW SUBMARINE");
    let expected = Bytes::from("YELLOW SUBMARINE\x04\x04\x04\x04");

    assert_eq!(input.pad(20), expected);

    ok()
}

// I realize I am doing challenge 10 the other way around (encrypt vs. decrypt)
// However, for future challanges, it is more useful to implement encrypt
#[test]
fn challenge_10() -> TestResult {
    // Input
    let plaintext = funky_music()?;
    let key = aes::Block::new(*b"YELLOW SUBMARINE");

    // Expected output
    let file = FileLineIterator::new("../../data/10.txt")?;
    let ciphertext = Bytes::try_from_base64(file)?;

    assert_eq!(aes::cbc::encrypt(&plaintext, &key), ciphertext);

    ok()
}

#[test]
fn challenge_11() {
    // Re-run the test multiple times, since the oracle involves randomness
    for _ in 0..16 {
        let oracle = oracle::RandomBlockMode::default();

        let detected_mode = adversary::detect_aes_block_mode(&oracle);

        assert_eq!(&detected_mode, oracle.block_mode());
    }
}

#[test]
fn challenge_12() {
    let oracle = oracle::EcbFixedPostfix::default();

    // It is known that the oracle uses ECB, but verify anyway.
    let detected_mode = adversary::detect_aes_block_mode(&oracle);
    assert_eq!(&detected_mode, &aes::BlockMode::Ecb);

    // TODO: write adversary to attack the fixed postfix
}
