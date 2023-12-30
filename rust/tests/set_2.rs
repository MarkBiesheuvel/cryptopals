use cryptopals::{aes, oracle, Bytes};
// Test support
use support::{funky_music, ok, FileLineIterator, TestResult};
mod support;

#[test]
fn challenge_9() -> TestResult {
    let mut input = Bytes::from("YELLOW SUBMARINE");
    let expected = Bytes::from("YELLOW SUBMARINE\x04\x04\x04\x04");

    // In-place pad operation
    input.pad(20);

    assert_eq!(input, expected);

    ok()
}

// I realize I am doing challenge 10 the other way around (encrypt vs. decrypt)
// However, for future challanges, it is more useful to implement encrypt
#[test]
fn challenge_10() -> TestResult {
    // Input
    let plaintext = funky_music()?;
    let key = Bytes::from("YELLOW SUBMARINE");

    // Expected output
    let file = FileLineIterator::new("../data/10.txt")?;
    let ciphertext = Bytes::try_from_base64(file)?;

    assert_eq!(aes::cbc::encrypt(&plaintext, &key), ciphertext);

    ok()
}

#[test]
fn challenge_11() -> TestResult {
    let oracle = oracle::RandomBlockMode::default();

    // TODO: implement adversary
    let plaintext = Bytes::from("Hello, World!");
    println!("{:?}", oracle.encrypt(plaintext));

    ok()
}
