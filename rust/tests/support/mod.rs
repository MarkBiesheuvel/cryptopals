use std::error::Error;

use cryptopals::{Bytes, Hexadecimal};
pub use file_line_iterator::FileLineIterator;

mod file_line_iterator;

pub fn funky_music() -> Result<Bytes, Box<dyn Error>> {
    // Load content from file
    let file = FileLineIterator::new("../data/n2Ubq9XII8c.txt")?;

    // Parse as hexadecimal
    let bytes = Bytes::try_from(Hexadecimal::from(file))?;

    // Return result
    Ok(bytes)
}
