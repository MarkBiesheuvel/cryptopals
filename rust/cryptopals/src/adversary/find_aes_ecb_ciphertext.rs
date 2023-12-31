use super::average_hamming_distance;
use crate::{aes, Bytes, CryptopalsError, ScoredBox};

/// Adversary which takes a list of candidates and returns the one which is most
/// likely to be an AES ECB-mode encrypted ciphertext
///
/// Assumption: the plaintext is human-readable text, i.e. mostly alphanumeric
/// characters Therefore the hamming distance between characters is lower
/// compared to random data With ECB if blocks contain the same data, they will
/// lead to the same result So we are looking for a cipher with a low average
/// hamming distance across blocks
pub fn find_aes_ecb_ciphertext(candidates: Vec<Bytes>) -> Result<Bytes, CryptopalsError> {
    let scores = candidates
        .into_iter()
        .map(|candidate| {
            // Calculate average hamming distance for each candidate
            let score = average_hamming_distance(&candidate, aes::BLOCK_LENGTH)?;
            let scored_box = ScoredBox::new(score, candidate);
            Ok(scored_box)
        })
        .collect::<Result<Vec<ScoredBox<Bytes>>, CryptopalsError>>()?;

    // Find the candidate with the lowest score, unbox it, and return it
    scores
        .into_iter()
        .min()
        .map(ScoredBox::unbox)
        .ok_or(CryptopalsError::UnableToFindLikelyCandidate)
}
