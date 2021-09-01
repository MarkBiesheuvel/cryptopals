from typing import Iterable
from math import ceil
from string import ascii_lowercase, ascii_uppercase, printable
from itertools import combinations
from .operations import single_byte_xor, fixed_xor

# Number of chunks to compare to eachother using Hamming distance in order to guess the key length of a repeating key
NUMBER_OF_CHUNKS = 6

# Source: http://norvig.com/mayzner.html
# Since the dataset contained roughly 743 B words, I added 743 B spaces to the set and recalculated all frequencies
# For example, the frequency of the space itself becomes 743.8 B / (3,563 B + 743 B) = 17.27%
# And the frequency of the letter A becomes 286.5 B / (3,563 B + 743 B) = 6.65%
LETTER_FREQUENCY = {
    ' ': 0.1727, 'e': 0.1034, 't': 0.0768, 'a': 0.0665, 'o': 0.0632, 'i': 0.0626, 'n': 0.0599, 's': 0.0539, 'r': 0.0520,
    'h': 0.0418, 'l': 0.0337, 'd': 0.0316, 'c': 0.0277, 'u': 0.0226, 'm': 0.0208, 'f': 0.0199, 'p': 0.0177, 'g': 0.0155,
    'w': 0.0139, 'y': 0.0138, 'b': 0.0123, 'v': 0.0087, 'k': 0.0045, 'x': 0.0020, 'j': 0.0013, 'q': 0.0010, 'z': 0.0007,
}


# Function to score a character with the likelyhood of it being part of a plain text string
def score(byte: int) -> float:
    character: str = chr(byte)

    # TODO: implement chi-squared test as suggested in https://crypto.stackexchange.com/a/30259
    if character in ascii_lowercase:
        return LETTER_FREQUENCY[character]
    else:
        # Don't count uppercase letters, non-ascii letters or punctuation
        return 0


def hamming_distance(input_a: bytes, input_b: bytes) -> int:
    # By computing the XOR, all bits that were different are 1, all bits that were the same are zero
    difference = fixed_xor(input_a, input_b)

    return sum(
        (byte >> i) & 1  # Count the bit if it is 1 (and thus was different)
        for byte in difference
        for i in range(8)  # Eight bits in a byte
    )


def average_hamming_distance(cipher: bytes, length: int) -> float:
    # First four chucks of $length
    chunks = (cipher[i*length:(i+1)*length] for i in range(NUMBER_OF_CHUNKS))

    # Combine each chunk with to others
    combos = list(combinations(chunks, 2))

    # Calculate the average hamming distance
    return sum(
        hamming_distance(chunk_a, chunk_b) / length
        for chunk_a, chunk_b in combos
    ) / len(combos)


# Function to find the most likely plain text out of a iterator of candidates
def best_candidate(candidates: Iterable[bytes]) -> bytes:
    # Filter out any candidates with non-printable characters
    candidates = filter(
        lambda candidate: all(chr(byte) in printable for byte in candidate),
        candidates
    )

    # TODO: handle error if no candidate is left over (i.e. probably the key was incorrect)

    return max(
        candidates,
        key=lambda candidate: sum(score(character) for character in candidate),
    )


# Function that tries all one-byte keys against every cipher to find the most likely plain text
def single_byte_xor_ciphers(ciphers: Iterable[bytes]) -> bytes:
    # Iterate over all one-byte values and try to XOR it with the cipher
    candidates: Iterable[bytes] = (
        single_byte_xor(cipher, byte)
        for cipher in ciphers
        for byte in range(256)
    )

    # Encode bytes as string
    return best_candidate(candidates)


def repeating_key_xor_cipher(cipher: bytes, max_key_length: int) -> bytes:
    cipher_length: int = len(cipher)

    # This analysis does not work if there are no repeats
    if max_key_length > cipher_length / NUMBER_OF_CHUNKS:
        raise Exception('Invalid operation')

    # Find the key length with the lowest normalized hamming distance between the first and second block
    key_length: int = min(
        range(2, max_key_length),
        key=lambda length: average_hamming_distance(cipher, length)
    )

    # Split cipher up into blocks where each block $i contains bytes from cipher at position $(i % key_length)
    cipher_blocks: Iterable[bytes] = (
        bytes(
            cipher[j]
            for j in range(i, cipher_length, key_length)
        )
        for i in range(key_length)
    )

    # Analyse each block as a single byte XOR cipher
    plain_text_blocks: List[bytes] = [
        single_byte_xor_ciphers([block])
        for block in cipher_blocks
    ]

    # Reconstruct the plain text by placing all bytes back into the original order
    plain_text: bytes = bytes(
        plain_text_blocks[i % key_length][i // key_length]
        for i in range(cipher_length)
    )

    return plain_text


def detect_aes_ecb_mode(ciphers: Iterable[bytes]) -> bytes:
    # 128 bit key, so 16 bytes
    key_length = 16

    return min(
        ciphers,
        key=lambda cipher: average_hamming_distance(cipher, key_length)
    )
