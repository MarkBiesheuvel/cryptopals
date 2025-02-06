#[derive(Debug)]
pub enum EncodingError {
    InvalidLength(usize),
    InvalidCharacter(char),
}
