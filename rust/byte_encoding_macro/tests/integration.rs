use byte_encoding_macro::hex;

#[test]
fn valid_hex_does_compile() {
    let bytes: [u8; 4] = hex!("A0 CD 2F FF");

    assert_eq!(bytes[0], 160);
    assert_eq!(bytes[3], 255);
}
