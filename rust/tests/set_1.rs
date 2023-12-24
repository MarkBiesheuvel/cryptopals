use std::error::Error;

use cryptopals::{adversary, aes, Bytes};
// Test support
use support::{ok, FileLineIterator, TestResult};
mod support;

/// Returns the lyrics to Funky Music as a Bytes struct
pub fn funky_music() -> Result<Bytes, Box<dyn Error>> {
    // Load content from file
    let file = FileLineIterator::new("../data/n2Ubq9XII8c.txt")?;

    // Parse as hexadecimal
    let bytes = Bytes::try_from_hexadecimal(file)?;

    // Return result
    Ok(bytes)
}

#[test]
fn challenge_1() -> TestResult {
    // Convert as hexadecimal and base64 respectively
    let value_1 = Bytes::try_from_hexadecimal(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
    )?;
    let value_2 = Bytes::try_from_base64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")?;

    // Both values should be equal
    assert_eq!(value_1, value_2);

    ok()
}

#[test]
fn challenge_2() -> TestResult {
    // Convert as hexadecimal
    let input_1 = Bytes::try_from_hexadecimal("1c0111001f010100061a024b53535009181c")?;
    let input_2 = Bytes::try_from_hexadecimal("686974207468652062756c6c277320657965")?;
    let expected = Bytes::try_from_hexadecimal("746865206b696420646f6e277420706c6179")?;

    // Fixed XOR should lead to expected value
    assert_eq!(input_1.fixed_xor(&input_2)?, expected);

    ok()
}

#[test]
fn challenge_3() -> TestResult {
    // Ciphertext as hexadecimal
    let ciphertext =
        Bytes::try_from_hexadecimal("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;

    // Expected plaintext
    let expected = Bytes::from("Cooking MC's like a pound of bacon");

    assert_eq!(adversary::attack_single_byte_xor(&ciphertext)?, expected);

    ok()
}

#[test]
fn challenge_4() -> TestResult {
    let lines = FileLineIterator::new("../data/4.txt")?;

    // Convert each line from hexadecimal encoded string to Bytes
    let lines = lines
        .map(|line| Bytes::try_from_hexadecimal(line))
        .collect::<Result<Vec<_>, _>>()?;

    // Try to find the most likely candidate and skip any ciphertext for which no
    // valid answer was found
    let candidates = lines
        .iter()
        .filter_map(|ciphertext| adversary::attack_single_byte_xor(&ciphertext).ok())
        .collect::<Vec<_>>();

    let expected = Bytes::from("Now that the party is jumping\n");

    assert_eq!(adversary::find_english_text(candidates)?, expected);

    ok()
}

#[test]
fn challenge_5() -> TestResult {
    // Input
    let key = Bytes::from("ICE");
    let plaintext = Bytes::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");

    // Expected output
    let ciphertext = Bytes::try_from_hexadecimal("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")?;

    assert_eq!(plaintext.repeated_key_xor(&key), ciphertext);

    ok()
}

#[test]
fn challenge_6() -> TestResult {
    // Input
    let file = FileLineIterator::new("../data/6.txt")?;
    let ciphertext = Bytes::try_from_base64(file)?;

    // Expected output
    let plaintext = funky_music()?;

    assert_eq!(adversary::attack_repeating_key_xor(&ciphertext)?, plaintext);

    ok()
}

// I realize I am doing challenge 7 the other way around (encrypt vs. decrypt)
#[test]
fn challenge_7() -> TestResult {
    // Input
    let plaintext = funky_music()?;
    let key = Bytes::from("YELLOW SUBMARINE");

    // Expected output
    let file = FileLineIterator::new("../data/7.txt")?;
    let ciphertext = Bytes::try_from_base64(file)?;

    assert_eq!(aes::ecb::encrypt(&plaintext, &key)?, ciphertext);

    ok()
}

#[test]
fn challenge_8() -> TestResult {
    let lines = FileLineIterator::new("../data/8.txt")?;

    // Convert each line from hexadecimal encoded string to Bytes
    let candidates = lines
        .map(|line| Bytes::try_from_hexadecimal(line))
        .collect::<Result<Vec<_>, _>>()?;

    // Expected output
    let expected = Bytes::from([
        216, 128, 97, 151, 64, 168, 161, 155, 120, 64, 168, 163, 28, 129, 10, 61, 8, 100, 154, 247, 13, 192, 111, 79,
        213, 210, 214, 156, 116, 76, 210, 131, 226, 221, 5, 47, 107, 100, 29, 191, 157, 17, 176, 52, 133, 66, 187, 87,
        8, 100, 154, 247, 13, 192, 111, 79, 213, 210, 214, 156, 116, 76, 210, 131, 148, 117, 201, 223, 219, 193, 212,
        101, 151, 148, 157, 156, 126, 130, 191, 90, 8, 100, 154, 247, 13, 192, 111, 79, 213, 210, 214, 156, 116, 76,
        210, 131, 151, 169, 62, 171, 141, 106, 236, 213, 102, 72, 145, 84, 120, 154, 107, 3, 8, 100, 154, 247, 13, 192,
        111, 79, 213, 210, 214, 156, 116, 76, 210, 131, 212, 3, 24, 12, 152, 200, 246, 219, 31, 42, 63, 156, 64, 64,
        222, 176, 171, 81, 178, 153, 51, 242, 193, 35, 197, 131, 134, 176, 111, 186, 24, 106,
    ]);

    assert_eq!(adversary::find_aes_ecb_ciphertext(candidates)?, expected);

    ok()
}
