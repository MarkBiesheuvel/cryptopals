use super::{byte_operator::sub_byte, Block, BLOCK_LENGTH};

// AES uses 10 rounds for 128-bit keys, plus 1 for the initial key
const NUMBER_OF_ROUNDS: usize = 11;

// Round constants from Rijndael key schedule
const ROUND_CONSTANTS: [u8; 11] = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54];

/// TODO: docs
pub struct Key(Vec<Block>);

impl Default for Key {
    /// Keys are initialized with random values
    fn default() -> Key {
        // Generate a random initial value
        let mut rng = rand::thread_rng();
        let initial_value = Block::with_random_values(&mut rng);

        Key::new(initial_value)
    }
}

impl<B> From<B> for Key
where
    B: Into<Block>,
{
    fn from(value: B) -> Key {
        Key::new(value.into())
    }
}

impl Key {
    /// TODO: docs
    pub fn new(initial_value: Block) -> Key {
        // Initialize with none of the rounds expanded
        let mut round_keys = Vec::with_capacity(NUMBER_OF_ROUNDS);

        // Push initial value
        round_keys.push(initial_value);

        // Iterate over the number of rounds
        for round_number in 1..NUMBER_OF_ROUNDS {
            // Round constant
            let constant = ROUND_CONSTANTS[round_number];

            // Get previous round key
            let prev = round_keys.get(round_number - 1).unwrap();

            // Start with a blank slate
            let mut next = [0; BLOCK_LENGTH];

            // W[i] = W[i-4] XOR SubWord(RotWord(W[i-1]))
            next[0] = prev[0] ^ sub_byte(prev[13]) ^ constant;
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

    /// TODO: docs
    pub fn iter(&self) -> impl Iterator<Item = &Block> {
        self.0.iter()
    }
}
