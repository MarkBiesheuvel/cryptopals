use std::error::Error;

use cryptopals::Bytes;
pub use file_line_iterator::FileLineIterator;

mod file_line_iterator;

/// Type alias for return type of test
pub type TestResult = Result<(), Box<dyn Error>>;

/// Returns Ok with the correct type
pub fn ok() -> TestResult {
    Ok::<(), Box<dyn Error>>(())
}

/// Returns the lyrics to Funky Music as a Bytes struct
#[allow(dead_code)]
pub fn funky_music() -> Result<Bytes, Box<dyn Error>> {
    // Load content from file
    let file = FileLineIterator::new("../data/n2Ubq9XII8c.txt")?;

    // Parse as hexadecimal
    let bytes = Bytes::try_from_hexadecimal(file)?;

    // Return result
    Ok(bytes)
}
