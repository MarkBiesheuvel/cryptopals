use std::iter::Iterator;
use std::path::Path;
use std::{fs, io, io::BufRead};

/// Wrapper around file reader for test data files
pub struct TestFile(io::BufReader<fs::File>);

impl TestFile {
    pub fn new<P>(path: P) -> TestFile
    where
        P: AsRef<Path>,
    {
        let file_reader = fs::File::open(path).expect("test case should specify valid file path");
        let buffered_reader = io::BufReader::new(file_reader);

        TestFile(buffered_reader)
    }

    pub fn lines(self) -> impl Iterator<Item = String> {
        // Use `BufReader::lines`
        self.0
            .lines()
            .map(|result| result.expect("there should be no I/O errors in test cases"))
    }

    pub fn to_string(self) -> String {
        // Use `BufReader::lines` instead `Read::read_to_end` in order to remove newline characters
        self.lines().fold(String::new(), |mut acc, line| {
            acc.push_str(&line);
            acc
        })
    }
}
