use byte_encoding_macro::{base64, hex};
use cryptopals::{adversary, aes, byte::*};
// Test support
use support::{from_base64, from_hexadecimal, funky_music, TestFile};
mod support;

#[test]
fn challenge_1() {
    // value in hexadecimal and base64 respectively
    let a = hex!("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let b = base64!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");

    // Both values should be equal
    assert_eq!(a, b);
}

#[test]
fn challenge_2() {
    // Convert as hexadecimal
    let input_1 = ByteArray::from(hex!("1c0111001f010100061a024b53535009181c"));
    let input_2 = ByteArray::from(hex!("686974207468652062756c6c277320657965"));
    let expected = ByteArray::from(hex!("746865206b696420646f6e277420706c6179"));

    // Fixed XOR should lead to expected value
    assert_eq!(input_1 ^ input_2, expected);
}

#[test]
fn challenge_3() {
    // Ciphertext as hexadecimal
    let ciphertext =
        ByteSlice::from(hex!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").as_ref());

    // Expected plaintext
    let expected = ByteSlice::from("Cooking MC's like a pound of bacon");

    // Attack the ciphertext
    let result = adversary::attack_single_byte_xor(&ciphertext).expect("adversary should be successful");

    assert_eq!(result, expected);
}

#[test]
fn challenge_4() {
    let candidates = TestFile::new("../../data/4.txt")
        // Iterate over each line
        .lines()
        // Convert from hexadecimal to `ByteSlice`
        .map(from_hexadecimal)
        // Attach each line as if it where encrypted with single byte XOR
        .map(|ciphertext| adversary::attack_single_byte_xor(&ciphertext))
        // Filter out any lines which did not yield a `Result::Ok`
        .filter_map(|result| result.ok())
        // Collect
        .collect();

    let expected = ByteSlice::from("Now that the party is jumping\n");

    // Attack the ciphertext
    let result = adversary::find_english_text(candidates).expect("adversary should be successful");

    assert_eq!(result, expected);
}

#[test]
fn challenge_5() {
    // Input
    let key = ByteSlice::from("ICE");
    let plaintext = ByteSlice::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");

    // Expected output
    let ciphertext = ByteSlice::from(hex!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").as_ref());

    assert_eq!(plaintext.repeated_key_xor(&key), ciphertext);
}

#[test]
fn challenge_6() {
    // Input
    let ciphertext = from_base64(TestFile::new("../../data/6.txt").to_string());

    // Expected output
    let plaintext = funky_music();

    // Attack the ciphertext
    let result = adversary::attack_repeating_key_xor(&ciphertext).expect("adversary should be successful");

    assert_eq!(result, plaintext);
}

#[test]
fn challenge_7() {
    // Input
    let key = aes::Key::from(*b"YELLOW SUBMARINE");
    let plaintext = funky_music();

    let ciphertext = from_base64(TestFile::new("../../data/7.txt").to_string());

    // Verify both encrypt and decrypt
    assert_eq!(aes::ecb::encrypt(plaintext.clone(), &key), ciphertext);
    assert_eq!(aes::ecb::decrypt(ciphertext, &key).unwrap(), plaintext);
}

#[test]
fn challenge_8() {
    let candidates = TestFile::new("../../data/8.txt")
        // Iterate over each line
        .lines()
        // Convert from hexadecimal to `ByteSlice`
        .map(from_hexadecimal)
        // Collect
        .collect();

    // Expected output
    let expected = ByteSlice::from(
        [
            216, 128, 97, 151, 64, 168, 161, 155, 120, 64, 168, 163, 28, 129, 10, 61, 8, 100, 154, 247, 13, 192, 111,
            79, 213, 210, 214, 156, 116, 76, 210, 131, 226, 221, 5, 47, 107, 100, 29, 191, 157, 17, 176, 52, 133, 66,
            187, 87, 8, 100, 154, 247, 13, 192, 111, 79, 213, 210, 214, 156, 116, 76, 210, 131, 148, 117, 201, 223,
            219, 193, 212, 101, 151, 148, 157, 156, 126, 130, 191, 90, 8, 100, 154, 247, 13, 192, 111, 79, 213, 210,
            214, 156, 116, 76, 210, 131, 151, 169, 62, 171, 141, 106, 236, 213, 102, 72, 145, 84, 120, 154, 107, 3, 8,
            100, 154, 247, 13, 192, 111, 79, 213, 210, 214, 156, 116, 76, 210, 131, 212, 3, 24, 12, 152, 200, 246, 219,
            31, 42, 63, 156, 64, 64, 222, 176, 171, 81, 178, 153, 51, 242, 193, 35, 197, 131, 134, 176, 111, 186, 24,
            106,
        ]
        .as_ref(),
    );

    // Find the correct candidate
    let result = adversary::find_aes_ecb_ciphertext(candidates).expect("adversary should be successful");

    assert_eq!(result, expected);
}
