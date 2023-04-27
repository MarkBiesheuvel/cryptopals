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
