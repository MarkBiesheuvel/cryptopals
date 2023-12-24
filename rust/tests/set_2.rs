use cryptopals::Bytes;
// Test support
use support::{ok, TestResult};
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
