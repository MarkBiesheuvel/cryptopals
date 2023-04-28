use std::fmt;

/// Plaintext or ciphertext without any guarantees regarding block size
#[derive(Eq, PartialEq)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn fixed_xor(&self, other: &Bytes) -> Bytes {
        let bytes = (self.0.iter())
            .zip(other.0.iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect::<Vec<_>>();

        Bytes(bytes)
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(value: Vec<u8>) -> Self {
        Bytes(value)
    }
}

impl From<&str> for Bytes {
    fn from(value: &str) -> Self {
        Bytes(value.bytes().collect())
    }
}

impl fmt::Debug for Bytes {
    /// Custom debug function which displays Bytes as a human readable string
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut tuple = f.debug_tuple("Bytes");

        match String::from_utf8(self.0.clone()) {
            Ok(value) => {
                tuple.field(&value);
            }
            Err(_) => {
                // TODO: find a different way of representing invalid UTF-8 string
                tuple.field(&self.0);
            }
        };

        tuple.finish()
    }
}
