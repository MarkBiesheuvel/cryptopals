use crate::Bytes;

// Source: http://en.algoritmy.net/article/40379/Letter-frequency-English
const CHARACTER_FREQUENCY: [f32; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, // V-Z
];

// Inspiration: https://crypto.stackexchange.com/a/30259/103927
fn chi_squared(candidate: &Bytes) -> f32 {
    // Get length of input and convert to floating point for future calculation
    let length = candidate.length() as f32;

    // If length is zero, the chi-squared will be inf due to divide by zero
    if length == 0.0 {
        return f32::INFINITY;
    }

    // Start with all zeroes
    // Since the size is known (26), we can use an array instead of a HashMap
    let mut letter_counts = [0usize; 26];

    // Iterate over individual bytes
    for byte in candidate.iter() {
        // Turn byte value into a letter index
        let letter_index = match byte {
            // Convert uppercase character to index
            65..=90 => byte - 65,

            // Convert lowercase character to index
            97..=122 => byte - 97,

            // Ignore other printable characters
            9 | 10 | 13 | 32..=126 => continue,

            // Penalty for unprintable characters
            _ => {
                return f32::INFINITY;
            }
        } as usize;

        // Letter index is within bounds of the array
        assert!(letter_index < 26);

        // Increment count for letter
        letter_counts[letter_index] += 1;
    }

    // Sum over each letter
    (0..26)
        .map(|letter_index| {
            // Observed count as floating point number
            let observed = letter_counts[letter_index] as f32;

            // Calculate the expected count based on the "string" length
            let expected = CHARACTER_FREQUENCY[letter_index] * length;

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
