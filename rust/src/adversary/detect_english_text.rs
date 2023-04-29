use crate::Bytes;

// Dealing with 26 characters and whitespace
const SIZE: usize = 27;

// Source: http://norvig.com/mayzner.html
// Since the dataset contained roughly 743B words, I added 743B spaces to the
// set and recalculated all frequencies For example, the frequency of the space
// itself becomes 743.8B / (3,563B + 743B) = 17.27% And the frequency of the
// letter A becomes 286.5B / (3,563B + 743B) = 6.65%
const CHARACTER_FREQUENCY: [f32; SIZE] = [
    0.0665, // A
    0.0123, // B
    0.0277, // C
    0.0316, // D
    0.1034, // E
    0.0199, // F
    0.0155, // G
    0.0418, // H
    0.0626, // I
    0.0013, // J
    0.0045, // K
    0.0337, // L
    0.0208, // M
    0.0599, // N
    0.0632, // O
    0.0177, // P
    0.0010, // Q
    0.0520, // R
    0.0539, // S
    0.0768, // T
    0.0226, // U
    0.0087, // V
    0.0139, // W
    0.0020, // X
    0.0138, // Y
    0.0007, // Z
    0.1727, // whitespace
];

// Inspiration: https://crypto.stackexchange.com/a/30259/103927
fn chi_squared(candidate: &Bytes) -> f32 {
    // Get length of input and convert to floating point for future calculation
    let mut number_of_letters = 0;

    // Start with all zeroes
    // Since the size is known (27), we can use an array instead of a HashMap
    let mut letter_counts = [0usize; SIZE];

    // Iterate over individual bytes
    for byte in candidate.iter() {
        // Turn byte value into a letter index
        let letter_index = match byte {
            // Convert uppercase character to index
            65..=90 => byte - 65,

            // Convert lowercase character to index
            97..=122 => byte - 97,

            // Use whitespaces as our "27th character"
            9 | 10 | 13 | 32 => 26,

            // Ignore other printable characters
            33..=126 => continue,

            // Penalty for unprintable characters
            _ => {
                return f32::INFINITY;
            }
        } as usize;

        // Letter index is within bounds of the array
        assert!(letter_index < SIZE);

        // Increment total counter
        number_of_letters += 1;

        // Increment counter for letter
        letter_counts[letter_index] += 1;
    }

    // Convert to floating point for future calculations
    let number_of_letters = number_of_letters as f32;

    // Sum over each letter
    (0..SIZE)
        .map(|letter_index| {
            // Observed count as floating point number
            let observed = letter_counts[letter_index] as f32;

            // Calculate the expected count based on the "string" length
            let expected = CHARACTER_FREQUENCY[letter_index] * number_of_letters;

            // Compute the difference sqaured divived by expected
            let difference = observed - expected;
            difference * difference / expected
        })
        .sum()
}

/// Adversary which takes a list of candidates and returns the one which is most
/// likely to be English text
pub fn detect_english_text(candidates: Vec<Bytes>) -> Option<Bytes> {
    candidates
        .into_iter()
        .map(|candidate| {
            // Calculate chi squared score for each candidate
            let score = chi_squared(&candidate);

            // Return as tuple, so we can min by the score and return the candidate
            (candidate, score)
        })
        .min_by(|(_, score_lhs), (_, score_rhs)| {
            // Compare the scores of two candidates
            score_lhs.total_cmp(score_rhs)
        })
        .map(|(candidate, _)| {
            // Return the candidate (and drop the score)
            candidate
        })
}
