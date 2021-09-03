from typing import Iterable, List, Dict, Callable
from math import ceil
from string import ascii_lowercase, ascii_uppercase, printable
from itertools import combinations
from .operation import single_byte_xor, fixed_xor
from .aes import BlockCipherMode, BLOCK_SIZE

# Number of chunks to compare to eachother using Hamming distance in order to guess the key length of a repeating key
NUMBER_OF_CHUNKS: int = 6

# Source: http://norvig.com/mayzner.html
# Since the dataset contained roughly 743 B words, I added 743 B spaces to the set and recalculated all frequencies
# For example, the frequency of the space itself becomes 743.8 B / (3,563 B + 743 B) = 17.27%
# And the frequency of the letter A becomes 286.5 B / (3,563 B + 743 B) = 6.65%
LETTER_FREQUENCY: Dict[str, float] = {
    ' ': 0.1727, 'e': 0.1034, 't': 0.0768, 'a': 0.0665, 'o': 0.0632, 'i': 0.0626, 'n': 0.0599, 's': 0.0539, 'r': 0.0520,
    'h': 0.0418, 'l': 0.0337, 'd': 0.0316, 'c': 0.0277, 'u': 0.0226, 'm': 0.0208, 'f': 0.0199, 'p': 0.0177, 'g': 0.0155,
    'w': 0.0139, 'y': 0.0138, 'b': 0.0123, 'v': 0.0087, 'k': 0.0045, 'x': 0.0020, 'j': 0.0013, 'q': 0.0010, 'z': 0.0007,
}

# "Carefully" chosen input string for detecting AES ECB block mode
# The string contains an arbitrary character 64 times in a row; in this case it's 64 times "0x55"
# After encrypting this plaintext with AES ECB mode, the cipher should have at least two repeated blocks of 16 bytes
AES_BLOCK_MODE_DETECTION_STRING: bytes = b'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU'


# Function to score a character with the likelyhood of it being part of the plaintext
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


# Function to find the most likely plaintext out of a iterator of candidates
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


# Function that brute forces a one-byte keys against every cipher to find the most likely plaintext
def brute_force_single_byte_xor(ciphers: Iterable[bytes]) -> bytes:
    # Iterate over all one-byte values and try to XOR it with the cipher
    candidates: Iterable[bytes] = (
        single_byte_xor(cipher, byte)
        for cipher in ciphers
        for byte in range(256)
    )

    # Encode bytes as string
    return best_candidate(candidates)


# Function that determines the most likely key length and brute forces each byte of the key
def brute_force_repeating_key_xor(cipher: bytes, max_key_length: int) -> bytes:
    cipher_length: int = len(cipher)

    # This analysis does not work if there are not enough chunks
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
    plaintext_blocks: List[bytes] = [
        brute_force_single_byte_xor([block])
        for block in cipher_blocks
    ]

    # Reconstruct the plaintext by placing all bytes back into the original order
    plaintext: bytes = bytes(
        plaintext_blocks[i % key_length][i // key_length]
        for i in range(cipher_length)
    )

    return plaintext


# Function that detects the cipher which is most likely encrypted using ECB mode
def detect_aes_ecb_cipher(ciphers: Iterable[bytes]) -> bytes:
    return min(
        ciphers,
        key=lambda cipher: average_hamming_distance(cipher, BLOCK_SIZE)
    )


# Function that detect whether a cipher was encrypted with either ECB or CBC block mode
# NOTE: The cipher needs to be generated with the plaintext $AES_BLOCK_MODE_DETECTION_STRING,
def detect_aes_block_mode(cipher: bytes) -> BlockCipherMode:
    # Try to find any two concecutive bytes which are completly idencital
    any_duplicate_bytes: bool = any(
        all(
            # Compare the $j'th byte of the current block with the $j'th byte of the previous block
            cipher[j - BLOCK_SIZE] == cipher[j]
            for j in range(i, i + BLOCK_SIZE)
        )
        # Iterate over all blocks except the first one (since we look back to the previous block)
        for i in range(BLOCK_SIZE, len(cipher), BLOCK_SIZE)
    )

    return BlockCipherMode.ECB if any_duplicate_bytes else BlockCipherMode.CBC


def brute_force_ecb_fixed_key_unknown_string(encrypt: Callable[[bytes], bytes]) -> bytes:
    dictionary: Dict[bytes, bytes]

    # Starting with no known characters
    known_characters: List[int] = []

    # TODO: determine the block size
    block_size: int = BLOCK_SIZE

    # TODO: truncate known_characters if it's longer than the $block_size
    prefix: List[int] = ([0] * (block_size - 1)) + known_characters

    # Create plaintext for the prefix followed by each byte value
    plaintext_combos = (
        bytes(prefix + [byte_value])
        for byte_value in range(255)
    )

    # Let the oracle encrypt each plaintext
    plaintext_cipher_pairs = (
        (plaintext, encrypt(plaintext))
        for plaintext in plaintext_combos
    )

    # Store the first block of the cipher with the corresponding plaintext
    dictionary = {
        cipher[:block_size]: plaintext
        for plaintext, cipher in plaintext_cipher_pairs
    }

    # Lookup the cipher of just the prefix and look it up in the dictionary
    # This will give us the value of one of the bytes of the unknown string
    character = dictionary[encrypt(bytes(prefix))[:block_size]][-1]

    # TODO: iterate until all characters of the unknown string are deciphered
    known_characters.append(character)

    return bytes(known_characters)
