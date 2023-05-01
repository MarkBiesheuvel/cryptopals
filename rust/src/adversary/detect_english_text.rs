use crate::Bytes;

// 26 letters plus 4 categories (whitespace, numbers, punctuation, symbols)
const SIZE: usize = 30;

// Most frequency analysis only focusses on letters.
// However, plaintext candidates with a high number of uncommon symbols are
// unlikely to be English plaintext. Therefore, I performed my own frequency
// analysis on a freely available plaintext; the "Alcoholics Anonymous".
// Source: https://anonpress.org/plain_text
const EXPECTED_FREQUENCY: [f32; SIZE] = [
    0.0590, // A
    0.0120, // B
    0.0216, // C
    0.0297, // D
    0.0994, // E
    0.0189, // F
    0.0143, // G
    0.0471, // H
    0.0576, // I
    0.0008, // J
    0.0065, // K
    0.0357, // L
    0.0205, // M
    0.0520, // N
    0.0658, // O
    0.0148, // P
    0.0007, // Q
    0.0442, // R
    0.0511, // S
    0.0684, // T
    0.0253, // U
    0.0086, // V
    0.0214, // W
    0.0014, // X
    0.0169, // Y
    0.0004, // Z
    0.1805, // whitespace
    0.0003, // numbers
    0.0214, // punctuation
    0.0036, // symbols
];

/// Code points are grouped into categories.
/// Return the index of the category of the code point.
fn index(code_point: &u8) -> Option<usize> {
    match code_point {
        // Uppercase characters
        65..=90 => Some(*code_point as usize - 65),

        // Lowercase characters
        97..=122 => Some(*code_point as usize - 97),

        // Whitespace
        9 | 10 | 13 | 32 => Some(26),

        // Numbers
        48..=57 => Some(27),

        // Punctuation
        33 | 44 | 46 | 63 => Some(28),

        // Symbols (everything else)
        34..=126 => Some(29),

        // Unprintable characters
        _ => None,
    }
}

/// Calculate score for candidate based on how closely it resembles English
/// text. The lower the score, the more resemblance to English.
/// Inspiration: https://crypto.stackexchange.com/a/30259/103927
fn chi_squared(candidate: &Bytes) -> f32 {
    // Start with all zeroes
    // Since the size is known, we can use an array instead of a HashMap
    let mut counts = [0usize; SIZE];

    // Iterate over individual bytes
    for byte in candidate.iter() {
        // Turn ASCII code points into an index
        let index = match index(byte) {
            Some(index) => index,
            None => {
                // Expected frequency is 0
                // Dividing by zero leads to chi-squared of infinity
                return f32::INFINITY;
            }
        };

        // Index is within bounds of the array
        assert!(index < SIZE);

        // Increment counter for index
        counts[index] += 1;
    }

    // Convert to floating point for future calculations
    let length = candidate.length() as f32;

    // Sum over each letter
    (0..SIZE)
        .map(|index| {
            // Observed count as floating point number
            let observed = counts[index] as f32;

            // Calculate the expected count based on the candidate length
            let expected = EXPECTED_FREQUENCY[index] * length;

            // Compute the difference squared divided by expected
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
