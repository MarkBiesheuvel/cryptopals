use std::iter::Iterator;
use std::{fs, io, io::BufRead};

/// Iterator over the lines of a file
pub struct FileLineIterator {
    reader: io::BufReader<fs::File>,
}

impl FileLineIterator {
    /// Constructor
    pub fn new(path: &str) -> io::Result<FileLineIterator> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);

        Ok(FileLineIterator { reader })
    }

    pub fn concat(self) -> String {
        self.fold(String::new(), |mut acc, line| {
            acc.push_str(&line);
            acc
        })
    }
}

impl Iterator for FileLineIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        // Create new String to hold the line
        let mut line = String::new();

        match self.reader.read_line(&mut line) {
            Ok(len) => {
                if len == 0 {
                    // Reached end of file
                    None
                } else {
                    // Remove last character if it's a New Line character
                    if line.ends_with('\n') {
                        line.pop();
                    }

                    // Remove last character if it's a Carriage Return character
                    if line.ends_with('\r') {
                        line.pop();
                    }

                    // Return remaining String
                    Some(line)
                }
            }

            // IO error
            Err(_) => None,
        }
    }
}
