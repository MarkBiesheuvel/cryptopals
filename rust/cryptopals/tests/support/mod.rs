#![allow(dead_code)]

use cryptopals::{
    byte::*,
    encoding::{Base64, Hexadecimal},
};
pub use test_file::TestFile;

mod test_file;

// Helper function to create `ByteSlice` from hexadecimal encoded string
pub fn from_hexadecimal<S>(value: S) -> ByteSlice<'static>
where
    S: AsRef<str>,
{
    ByteSlice::try_from(Hexadecimal::from(value.as_ref())).expect("test case should contain valid hexadecimal")
}

// Helper function to create `ByteSlice` from base64 encoded string
pub fn from_base64<S>(value: S) -> ByteSlice<'static>
where
    S: AsRef<str>,
{
    ByteSlice::try_from(Base64::from(value.as_ref())).expect("test case should contain valid base64")
}

// Returns the lyrics to Funky Music as a ByteSlice
pub fn funky_music() -> ByteSlice<'static> {
    // Load content from file
    let data = TestFile::new("../../data/n2Ubq9XII8c.txt").to_string();

    // Parse as hexadecimal
    ByteSlice::try_from(Hexadecimal::from(data)).expect("test file should contain valid hexadecimal")
}
