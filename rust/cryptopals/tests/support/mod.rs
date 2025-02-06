#![allow(dead_code)]

use byte_encoding::decode_hexadecimal;
use cryptopals::{byte::*, encoding::Base64};
pub use test_file::TestFile;

mod test_file;

// Helper function to create `ByteSlice` from hexadecimal encoded string
pub fn from_hexadecimal<S>(value: S) -> ByteSlice<'static>
where
    S: AsRef<str>,
{
    let bytes = decode_hexadecimal(value).expect("test case should contain valid hexadecimal");
    ByteSlice::from(bytes)
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
    let value = TestFile::new("../../data/n2Ubq9XII8c.txt").to_string();

    // Parse as hexadecimal
    from_hexadecimal(value)
}
