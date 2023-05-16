/// Set of operations that work using just an iterator over references to bytes
pub trait ByteIterable: From<Vec<u8>> {
    /// Retrun Iterator over bytes
    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a u8> + 'a>;

    /// Retrun the number of bytes
    fn length(&self) -> usize;

    /// XOR two Bytes with each other
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::{Bytes, ByteIterable};
    /// #
    /// let plaintext = Bytes::from("cryptopals");
    /// let key = Bytes::from([12, 34, 56, 78, 90, 123, 45, 67, 89, 10]);
    /// let ciphertext = Bytes::from([111, 80, 65, 62, 46, 20, 93, 34, 53, 121]);
    ///
    /// assert_eq!(plaintext.fixed_xor(&key), ciphertext);
    /// ```
    fn fixed_xor(&self, other: &Self) -> Self {
        let bytes = (self.iter())
            .zip(other.iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect();

        Self::from(bytes)
    }

    /// Hamming distance between two Bytes structs
    ///
    /// ## Examples
    /// ```
    /// # use cryptopals::{ByteIterable, Bytes};
    /// #
    /// let text_1 = Bytes::from("this is a test");
    /// let text_2 = Bytes::from("wokka wokka!!!");
    ///
    /// assert_eq!(text_1.hamming_distance(&text_2), 37);
    /// ```
    fn hamming_distance(&self, other: &Self) -> usize {
        // For each byte in length difference, there are 8 bits that "differ"
        let mut distance = 8 * self.length().abs_diff(other.length());

        // Count the bits that are different (the ones that are 1 after XOR)
        distance += self
            .fixed_xor(other)
            .iter()
            .map(|byte| {
                // Iterate over each bit
                let number_of_bites: u8 = (0..8).map(|i: u8| (byte >> i) & 1).sum();

                // For an individual byte the number of bits different is at most 8,
                // but when summing up a long array, the total might exceed the u8 primitive
                number_of_bites as usize
            })
            .sum::<usize>();

        distance
    }
}
