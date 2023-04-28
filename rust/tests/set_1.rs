use cryptopals::Bytes;

#[test]
fn challenge_1() {
    // Two input values
    let value_1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let value_2 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    // Convert as hexadecimal and base64 respectively
    let value_1 = Bytes::try_from_hexadecimal(value_1).unwrap();
    let value_2 = Bytes::try_from_base64(value_2).unwrap();

    // Both values should be equal
    assert_eq!(value_1, value_2);
}

#[test]
fn challenge_2() {
    // Two input values
    let input_1 = "1c0111001f010100061a024b53535009181c";
    let input_2 = "686974207468652062756c6c277320657965";
    let exptected = "746865206b696420646f6e277420706c6179";

    // Convert as hexadecimal
    let input_1 = Bytes::try_from_hexadecimal(input_1).unwrap();
    let input_2 = Bytes::try_from_hexadecimal(input_2).unwrap();
    let exptected = Bytes::try_from_hexadecimal(exptected).unwrap();

    // Fixed XOR should lead to expected value
    assert_eq!(input_1.fixed_xor(&input_2), exptected);
}
