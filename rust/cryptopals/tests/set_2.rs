use cryptopals::{aes, aes_block, oracle, Bytes};
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
    let key = aes_block!("YELLOW SUBMARINE");

    // Expected output
    let file = FileLineIterator::new("../../data/10.txt")?;
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
