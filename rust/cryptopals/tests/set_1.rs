use cryptopals::{
    adversary, aes,
    byte::*,
    encoding::{Base64, Hexadecimal},
};
// Test support
use support::{funky_music, ok, FileLineIterator, TestResult};
mod support;

#[test]
fn challenge_1() -> TestResult {
    // value in hexadecimal and base64 respectively
    let value_1 = Hexadecimal::from(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
    );
    let value_2 = Base64::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    // Convert both
    let value_1 = ByteSlice::try_from(value_1)?;
    let value_2 = ByteSlice::try_from(value_2)?;

    // Both values should be equal
    assert_eq!(value_1, value_2);

    ok()
}

#[test]
fn challenge_2() -> TestResult {
    // Convert as hexadecimal
    let input_1 = ByteSlice::try_from(Hexadecimal::from("1c0111001f010100061a024b53535009181c"))?;
    let input_2 = ByteSlice::try_from(Hexadecimal::from("686974207468652062756c6c277320657965"))?;
    let expected = ByteSlice::try_from(Hexadecimal::from("746865206b696420646f6e277420706c6179"))?;

    // Convert to statically sized byte sequences
    let input_1 = ByteArray::<18>::try_from(input_1)?;
    let input_2 = ByteArray::<18>::try_from(input_2)?;
    let expected = ByteArray::<18>::try_from(expected)?;

    // Fixed XOR should lead to expected value
    assert_eq!(input_1 ^ input_2, expected);

    ok()
}

#[test]
fn challenge_3() -> TestResult {
    // Ciphertext as hexadecimal
    let ciphertext = Hexadecimal::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let ciphertext = ByteSlice::try_from(ciphertext)?;

    // Expected plaintext
    let expected = ByteSlice::from("Cooking MC's like a pound of bacon");

    assert_eq!(adversary::attack_single_byte_xor(&ciphertext)?, expected);

    ok()
}

#[test]
fn challenge_4() -> TestResult {
    let lines = FileLineIterator::new("../../data/4.txt")?;

    // Convert each line from hexadecimal encoded string to Bytes
    let lines = lines
        .map(|line| ByteSlice::try_from(Hexadecimal::from(line)))
        .collect::<Result<Vec<_>, _>>()?;

    // Try to find the most likely candidate and skip any ciphertext for which no
    // valid answer was found
    let candidates = lines
        .iter()
        .filter_map(|ciphertext| adversary::attack_single_byte_xor(&ciphertext).ok())
        .collect::<Vec<_>>();

    let expected = ByteSlice::from("Now that the party is jumping\n");

    assert_eq!(adversary::find_english_text(candidates)?, expected);

    ok()
}

#[test]
fn challenge_5() -> TestResult {
    // Input
    let key = ByteSlice::from("ICE");
    let plaintext = ByteSlice::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");

    // Expected output
    let ciphertext = Hexadecimal::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    let ciphertext = ByteSlice::try_from(ciphertext)?;

    assert_eq!(plaintext.repeated_key_xor(&key), ciphertext);

    ok()
}

#[test]
fn challenge_6() -> TestResult {
    // Input
    let encoded_data = FileLineIterator::new("../../data/6.txt")?.concat();
    let ciphertext = ByteSlice::try_from(Base64::from(encoded_data))?;

    // Expected output
    let plaintext = funky_music()?;

    assert_eq!(adversary::attack_repeating_key_xor(&ciphertext)?, plaintext);

    ok()
}

// I realize I am doing challenge 7 the other way around (encrypt vs. decrypt)
// However, for future challenges, it is more useful to implement encrypt
#[test]
fn challenge_7() -> TestResult {
    // Input
    let plaintext = funky_music()?;
    let key = aes::Block::from(*b"YELLOW SUBMARINE");

    // Expected output
    let encoded_data = FileLineIterator::new("../../data/7.txt")?.concat();
    let ciphertext = ByteSlice::try_from(Base64::from(encoded_data))?;

    assert_eq!(aes::ecb::encrypt(plaintext, key), ciphertext);

    ok()
}

#[test]
fn challenge_8() -> TestResult {
    let lines = FileLineIterator::new("../../data/8.txt")?;

    // Convert each line from hexadecimal encoded string to Bytes
    let candidates = lines
        .map(|line| ByteSlice::try_from(Hexadecimal::from(line)))
        .collect::<Result<Vec<_>, _>>()?;

    // Expected output
    let expected = ByteSlice::from(
        &[
            216, 128, 97, 151, 64, 168, 161, 155, 120, 64, 168, 163, 28, 129, 10, 61, 8, 100, 154, 247, 13, 192, 111,
            79, 213, 210, 214, 156, 116, 76, 210, 131, 226, 221, 5, 47, 107, 100, 29, 191, 157, 17, 176, 52, 133, 66,
            187, 87, 8, 100, 154, 247, 13, 192, 111, 79, 213, 210, 214, 156, 116, 76, 210, 131, 148, 117, 201, 223,
            219, 193, 212, 101, 151, 148, 157, 156, 126, 130, 191, 90, 8, 100, 154, 247, 13, 192, 111, 79, 213, 210,
            214, 156, 116, 76, 210, 131, 151, 169, 62, 171, 141, 106, 236, 213, 102, 72, 145, 84, 120, 154, 107, 3, 8,
            100, 154, 247, 13, 192, 111, 79, 213, 210, 214, 156, 116, 76, 210, 131, 212, 3, 24, 12, 152, 200, 246, 219,
            31, 42, 63, 156, 64, 64, 222, 176, 171, 81, 178, 153, 51, 242, 193, 35, 197, 131, 134, 176, 111, 186, 24,
            106,
        ][..],
    );

    assert_eq!(adversary::find_aes_ecb_ciphertext(candidates)?, expected);

    ok()
}
