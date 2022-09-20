from typing import Iterable, Dict
from string import ascii_lowercase, printable
from .. import Ciphertext, Plaintext

# Source: http://norvig.com/mayzner.html
# Since the dataset contained roughly 743 B words, I added 743 B spaces to the set and recalculated all frequencies
# For example, the frequency of the space itself becomes 743.8 B / (3,563 B + 743 B) = 17.27%
# And the frequency of the letter A becomes 286.5 B / (3,563 B + 743 B) = 6.65%
LETTER_FREQUENCY: Dict[str, float] = {
    ' ': 0.1727, 'e': 0.1034, 't': 0.0768, 'a': 0.0665, 'o': 0.0632, 'i': 0.0626, 'n': 0.0599, 's': 0.0539, 'r': 0.0520,
    'h': 0.0418, 'l': 0.0337, 'd': 0.0316, 'c': 0.0277, 'u': 0.0226, 'm': 0.0208, 'f': 0.0199, 'p': 0.0177, 'g': 0.0155,
    'w': 0.0139, 'y': 0.0138, 'b': 0.0123, 'v': 0.0087, 'k': 0.0045, 'x': 0.0020, 'j': 0.0013, 'q': 0.0010, 'z': 0.0007,
}


# Function to score a character with the likelyhood of it being part of the plaintext
def score(byte: int) -> float:
    character: str = chr(byte)

    # TODO: implement chi-squared test as suggested in https://crypto.stackexchange.com/a/30259
    if character in ascii_lowercase:
        return LETTER_FREQUENCY[character]
    else:
        # Don't count uppercase letters, non-ascii letters or punctuation
        return 0


# Function to find the most likely plaintext out of a iterator of candidates
def find_likely_plaintext(plaintexts: Iterable[Plaintext]) -> Plaintext:
    # Filter out any candidates with non-printable characters
    printable_plaintexts: Iterable[Plaintext] = (plaintext for plaintext in plaintexts if plaintext.is_printable())

    try:
        return max(
            printable_plaintexts,
            key=lambda plaintext: sum(score(byte) for byte in plaintext.to_bytes()),
        )
    except ValueError:  # pragma: no cover
        raise Exception('None of the plaintexts are printable')


# Function that brute forces a one-byte keys against every cipher to find the most likely plaintext
def brute_force_single_byte_xor(ciphers: Iterable[Ciphertext]) -> Plaintext:
    # Iterate over all one-byte values and try to XOR it with the cipher
    candidate_plaintexts: Iterable[Plaintext] = (
        cipher.single_byte_xor(candidate_key, target_class=Plaintext)
        for cipher in ciphers
        for candidate_key in range(256)
    )

    # Find most likely plaintext
    return find_likely_plaintext(candidate_plaintexts)
