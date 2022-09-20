from typing import Iterable, List
from .average_hamming_distance import average_hamming_distance
from .brute_force_single_byte_xor import brute_force_single_byte_xor
from .. import Ciphertext, Plaintext


# Function that determines the most likely key length and brute forces each byte of the key
def brute_force_repeating_key_xor(ciphertext: Ciphertext, max_key_length: int) -> Plaintext:
    # Find the key length with the lowest normalized hamming distance between the first N blocks
    key_length: int = min(
        range(2, max_key_length),
        key=lambda key_length: average_hamming_distance(Ciphertext.from_text(ciphertext, block_size=key_length))
    )

    # Split cipher up into chunks where each chunk $i contains the bytes from cipher at position $(i % key_length)
    # Visualized: text=abcdefghi,key_length=3 -> [adg] [beh] [cfi]
    ciphertext_chunks: Iterable[Ciphertext] = (
        Ciphertext.from_iterable(
            ciphertext.get_byte(byte_index)
            for byte_index in range(chunk_index, ciphertext.length, key_length)
        )
        for chunk_index in range(key_length)
    )

    # Brute force each chunk as a single byte XOR cipher
    plaintext_chunks: List[Plaintext] = [
        brute_force_single_byte_xor([chunk])
        for chunk in ciphertext_chunks
    ]

    # Reconstruct the plaintext by placing all bytes back into the original order
    return Plaintext.from_iterable(
        plaintext_chunks[byte_index % key_length].get_byte(byte_index // key_length)
        for byte_index in range(ciphertext.length)
    )
