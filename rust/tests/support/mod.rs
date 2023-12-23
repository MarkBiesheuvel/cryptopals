use std::error::Error;

pub use file_line_iterator::FileLineIterator;

mod file_line_iterator;

/// Type alias for return type of test
pub type TestResult = Result<(), Box<dyn Error>>;

/// Returns Ok with the correct type
pub fn ok() -> TestResult {
    Ok::<(), Box<dyn Error>>(())
}
