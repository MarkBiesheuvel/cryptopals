use super::{byte_operator::sub_byte, Block, BLOCK_LENGTH};

/// AES uses 10 rounds for 128-bit keys, plus 1 for the initial key
pub const NUMBER_OF_ROUNDS: usize = 11;

// Round constants from Rijndael key schedule
const ROUND_CONSTANTS: [u8; 11] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

/// An AES 128-bit encryption key.
///
/// ## Examples
/// ```
/// use cryptopals::aes;
///
/// // Create random key
/// let mut rng = rand::thread_rng();
/// let random_key = aes::Key::with_random_values(&mut rng);
///
/// // Create manual key with same initial value
/// let (_, initial_value) = random_key.rounds().nth(0).unwrap();
/// let manual_key = aes::Key::from(initial_value.clone());
///
/// // Each round key should be equal
/// for (lhs, rhs) in random_key.rounds().zip(manual_key.rounds()) {
///     assert_eq!(lhs, rhs);
/// }
/// ```
pub struct Key(Vec<Block>);

impl<B> From<B> for Key
where
    B: Into<Block>,
{
    fn from(value: B) -> Key {
        Key::new(value.into())
    }
}

impl Key {
    /// Create keys with random values
    pub fn with_random_values(rng: &mut impl rand::Rng) -> Key {
        // Generate a random initial value
        let initial_value = Block::with_random_values(rng);

        Key::new(initial_value)
    }

    /// Key is automatically expanded to round keys
    fn new(initial_value: Block) -> Key {
        // Initialize with none of the rounds expanded
        let mut round_keys = Vec::with_capacity(NUMBER_OF_ROUNDS);

        // Push initial value
        round_keys.push(initial_value);

        // Iterate over the number of rounds
        for (round_number, round_constant) in ROUND_CONSTANTS.iter().enumerate().skip(1) {
            // Get previous round key
            let prev = round_keys.get(round_number - 1).unwrap();

            // Start with a blank slate
            let mut next = [0; BLOCK_LENGTH];

            // W[i] = W[i-4] XOR SubWord(RotWord(W[i-1]))
            next[0] = prev[0] ^ sub_byte(prev[13]) ^ round_constant;
            next[1] = prev[1] ^ sub_byte(prev[14]);
            next[2] = prev[2] ^ sub_byte(prev[15]);
            next[3] = prev[3] ^ sub_byte(prev[12]);

            // W[i] = W[i-4] XOR W[i-1]
            next[4] = prev[4] ^ next[0];
            next[5] = prev[5] ^ next[1];
            next[6] = prev[6] ^ next[2];
            next[7] = prev[7] ^ next[3];

            // W[i] = W[i-4] XOR W[i-1]
            next[8] = prev[8] ^ next[4];
            next[9] = prev[9] ^ next[5];
            next[10] = prev[10] ^ next[6];
            next[11] = prev[11] ^ next[7];

            // W[i] = W[i-4] XOR W[i-1]
            next[12] = prev[12] ^ next[8];
            next[13] = prev[13] ^ next[9];
            next[14] = prev[14] ^ next[10];
            next[15] = prev[15] ^ next[11];

            // Push next value
            round_keys.push(Block::from(next));
        }

        assert_eq!(round_keys.len(), NUMBER_OF_ROUNDS);

        Key(round_keys)
    }

    /// Double ended iterator over round keys, so it's possible to iterate in reverse
    /// TODO: consider returning a type `Round` which contains the round number and round key
    /// instead of the tuple (usize, &Block)
    pub fn rounds(&self) -> impl DoubleEndedIterator<Item = (usize, &Block)> {
        self.0.iter().enumerate()
    }
}
