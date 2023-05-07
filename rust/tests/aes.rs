use cryptopals::{aes, Bytes, Hexadecimal};

// Following the steps of https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf

#[test]
fn roundkey() {
    let key = aes::Roundkey::try_from("Thats my Kung Fu").unwrap();

    let expected_roundkeys = [
        "54 68 61 74 73 20 6D 79 20 4B 75 6E 67 20 46 75",
        "E2 32 FC F1 91 12 91 88 B1 59 E4 E6 D6 79 A2 93",
        "56 08 20 07 C7 1A B1 8F 76 43 55 69 A0 3A F7 FA",
        "D2 60 0D E7 15 7A BC 68 63 39 E9 01 C3 03 1E FB",
        "A1 12 02 C9 B4 68 BE A1 D7 51 57 A0 14 52 49 5B",
        "B1 29 3B 33 05 41 85 92 D2 10 D2 32 C6 42 9B 69",
        "BD 3D C2 87 B8 7C 47 15 6A 6C 95 27 AC 2E 0E 4E", // Mistake in PDF
        "CC 96 ED 16 74 EA AA 03 1E 86 3F 24 B2 A8 31 6A",
        "8E 51 EF 21 FA BB 45 22 E4 3D 7A 06 56 95 4B 6C",
        "BF E2 BF 90 45 59 FA B2 A1 64 80 B4 F7 F1 CB D8",
        "28 FD DE F8 6D A4 24 4A CC C0 A4 FE 3B 31 6F 26",
    ]
    .map(|string| Hexadecimal::from(string))
    .map(|hexadecimal| Bytes::try_from(hexadecimal).unwrap())
    .map(|bytes| aes::Block::try_from(&bytes).unwrap());

    // Verify each roundkey aginst expected value
    for (roundkey, expected) in key.zip(expected_roundkeys) {
        assert_eq!(roundkey, expected);
    }
}

#[test]
fn cipher() {
    let mut key = aes::Roundkey::try_from("Thats my Kung Fu").unwrap();
    let plaintext = aes::Block::try_from("Two One Nine Two").unwrap();

    // Expected state after each step
    let mut expected_states = [
        "00 1F 0E 54 3C 4E 08 59 6E 22 1B 0B 47 74 31 1A",
        "63 C0 AB 20 EB 2F 30 CB 9F 93 AF 2B A0 92 C7 A2",
        "63 2F AF A2 EB 93 C7 20 9F 92 AB CB A0 C0 30 2B",
        "BA 75 F4 7A 84 A4 8D 32 E8 8D 06 0E 1B 40 7D 5D",
        "58 47 08 8B 15 B6 1C BA 59 D4 E2 E8 CD 39 DF CE",
        "6A A0 30 3D 59 4E 9C F4 CB 48 98 9B BD 12 9E 8B",
        "6A 4E 98 8B 59 48 9E 3D CB 12 30 F4 BD A0 9C 9B", // Mistake in PDF
        "15 CE 89 65 C9 4D 71 47 7F 4B BE 97 9D C2 88 CD",
        "43 C6 A9 62 0E 57 C0 C8 09 08 EB FE 3D F8 7F 37",
    ]
    .into_iter()
    .map(|string| Hexadecimal::from(string))
    .map(|hexadecimal| Bytes::try_from(hexadecimal).unwrap())
    .map(|bytes| aes::Block::try_from(&bytes).unwrap());

    // Start with plaintext
    let mut state = plaintext;

    // Round 0 - Apply roundkey
    state ^= key.next().unwrap();
    assert_eq!(state, expected_states.next().unwrap());

    // Round 1 - Substitution bytes
    state.sub_bytes();
    assert_eq!(state, expected_states.next().unwrap());

    // Round 1 - Shift rows
    state.shift_rows();
    assert_eq!(state, expected_states.next().unwrap());

    // Round 1 - Mix columns
    state.mix_columns();
    assert_eq!(state, expected_states.next().unwrap());

    // Round 1 - Apply roundkey
    state ^= key.next().unwrap();
    assert_eq!(state, expected_states.next().unwrap());

    // Round 2 - Substitution bytes
    state.sub_bytes();
    assert_eq!(state, expected_states.next().unwrap());

    // Round 2 - Shift rows
    state.shift_rows();
    assert_eq!(state, expected_states.next().unwrap());

    // Round 2 - Mix columns
    state.mix_columns();
    assert_eq!(state, expected_states.next().unwrap());

    // Round 2 - Apply roundkey
    state ^= key.next().unwrap();
    assert_eq!(state, expected_states.next().unwrap());
}
