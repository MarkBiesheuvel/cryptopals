use cryptopals::{adversary, file, Base64, Bytes, Hexadecimal};

#[test]
fn challenge_1() {
    // Convert as hexadecimal and base64 respectively
    let value_1 = Bytes::try_from(Hexadecimal(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    ))
    .unwrap();
    let value_2 = Bytes::try_from(Base64(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
    ))
    .unwrap();

    // Both values should be equal
    assert_eq!(value_1, value_2);
}

#[test]
fn challenge_2() {
    // Convert as hexadecimal
    let input_1 = Bytes::try_from(Hexadecimal("1c0111001f010100061a024b53535009181c")).unwrap();
    let input_2 = Bytes::try_from(Hexadecimal("686974207468652062756c6c277320657965")).unwrap();
    let expected = Bytes::try_from(Hexadecimal("746865206b696420646f6e277420706c6179")).unwrap();

    // Fixed XOR should lead to expected value
    assert_eq!(input_1.fixed_xor(&input_2).unwrap(), expected);
}

#[test]
fn challenge_3() {
    // Ciphertext as hexadecimal
    let ciphertext = Bytes::try_from(Hexadecimal(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    ))
    .unwrap();

    // Expected plaintext
    let expected = Bytes::from("Cooking MC's like a pound of bacon");

    assert_eq!(
        adversary::attack_single_byte_xor(ciphertext).unwrap(),
        expected
    );
}

#[test]
fn challenge_4() {
    let lines = file::LineIterator::new("../data/4.txt").unwrap();

    let candidates = lines
        .map(|line| {
            // Convert the line into Bytes
            Bytes::try_from(Hexadecimal(&line)).unwrap()
        })
        .filter_map(|ciphertext| {
            // Try to find the most likely candidate and skip if it is None
            adversary::attack_single_byte_xor(ciphertext)
        })
        .collect::<Vec<_>>();

    let expected = Bytes::from("Now that the party is jumping\n");

    assert_eq!(
        adversary::detect_english_text(candidates).unwrap(),
        expected
    );
}
