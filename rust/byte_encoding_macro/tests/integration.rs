use byte_encoding_macro::{base64, hex};

#[test]
fn valid_hex_does_compile() {
    let bytes: [u8; 4] = hex!("26 73 74 72");

    assert_eq!(bytes[0], 38);
    assert_eq!(bytes[1], 115);
    assert_eq!(bytes[2], 116);
    assert_eq!(bytes[3], 114);
}

#[test]
fn valid_base64_does_compile() {
    let bytes: [u8; 4] = base64!("JnN0cg==");

    assert_eq!(bytes[0], 38);
    assert_eq!(bytes[1], 115);
    assert_eq!(bytes[2], 116);
    assert_eq!(bytes[3], 114);
}