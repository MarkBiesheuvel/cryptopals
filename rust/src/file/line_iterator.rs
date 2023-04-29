use std::{fs, io, io::BufRead};

pub struct LineIterator {
    reader: io::BufReader<fs::File>,
}

impl LineIterator {
    pub fn new(path: &str) -> io::Result<LineIterator> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);

        Ok(LineIterator { reader })
    }
}

impl Iterator for LineIterator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        // Create new string to hold the line
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
