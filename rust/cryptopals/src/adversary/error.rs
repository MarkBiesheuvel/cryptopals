use thiserror::Error;

/// Error enum for errors in adversary
#[derive(Error, Debug, PartialEq, Eq)]
pub enum AdversaryError {
    /// Unable to find a plaintext that only consists of printable characters.
    #[error("Unable to find a plaintext that only consists of printable characters.")]
    UnableToFindPrintablePlaintext,
    /// Unable to detect block size. (Ciphertext is too short.)
    #[error("Unable to detect block size. (Ciphertext is too short.)")]
    UnableToDetectBlockSize,
    /// Unable to calculate average hamming distance. (Ciphertext is too short.)
    #[error("Unable to calculate average hamming distance. (Ciphertext is too short.)")]
    UnableToCalculateAverageHammingDistance,
    /// The input list of candidates is empty. Cannot pick from empty list.
    #[error("The input list of candidates is empty. Cannot pick from empty list.")]
    EmptyCandidateList,
}
