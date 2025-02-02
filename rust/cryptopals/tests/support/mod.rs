use std::error::Error;

use cryptopals::{byte::*, encoding::Hexadecimal};
pub use file_line_iterator::FileLineIterator;

mod file_line_iterator;

/// Type alias for return type of test
pub type TestResult = Result<(), Box<dyn Error>>;

/// Returns Ok with the correct type
pub fn ok() -> TestResult {
    Ok::<(), Box<dyn Error>>(())
}

/// Returns the lyrics to Funky Music as a ByteSlice
#[allow(dead_code)]
pub fn funky_music() -> Result<ByteSlice<'static>, Box<dyn Error>> {
    // Load content from file
    let encoded_data = FileLineIterator::new("../../data/n2Ubq9XII8c.txt")?.concat();

    // Parse as hexadecimal
    let bytes = ByteSlice::try_from(Hexadecimal::from(encoded_data))?;

    // Return result
    Ok(bytes)
}
