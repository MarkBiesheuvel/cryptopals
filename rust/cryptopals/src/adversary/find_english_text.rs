use error_stack::{report, Result};

use super::AdversaryError;
use crate::{Bytes, ScoredBox};

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
fn char_index(code_point: &u8) -> Option<usize> {
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
        // Turn ASCII code points into a character index
        let index = match char_index(byte) {
            Some(index) => index,
            None => {
                // If byte does not map to a printable charachter, the expected frequency is 0.
                // Therefore, when calculating chi sqaured, dividing by 0 will lead to a score
                // of infinity.
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
    (counts.into_iter())
        .zip(EXPECTED_FREQUENCY.into_iter())
        .map(|(observed_count, expected_frequency)| {
            // Calculate the expected count based on the candidate length
            let expected_count = expected_frequency * length;

            // Compute the difference squared divided by expected count
            let difference = (observed_count as f32) - expected_count;
            difference * difference / expected_count
        })
        .sum()
}

/// Adversary which takes a list of candidates and returns the one which is most
/// likely to be English text
pub fn find_english_text(candidates: Vec<Bytes>) -> Result<Bytes, AdversaryError> {
    candidates
        .into_iter()
        // Calculate chi squared score for each candidate
        .map(|candidate| ScoredBox::new(chi_squared(&candidate), candidate))
        // Find the candidate with the lowest chi squared score
        .min()
        // Return the candidate
        .map(ScoredBox::unbox)
        // Map Option<_> to Result<_, _>
        .ok_or(report!(AdversaryError::UnableToFindPrintablePlaintext))
}
