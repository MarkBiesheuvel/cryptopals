from typing import Iterable, List
from .brute_force_single_byte_xor import brute_force_single_byte_xor
from ..operation import average_hamming_distance

# Number of blocks to compare to eachother to find the most likely key length
NUMBER_OF_BLOCKS: int = 6


# Function that determines the most likely key length and brute forces each byte of the key
def brute_force_repeating_key_xor(cipher: bytes, max_key_length: int) -> bytes:
    cipher_length: int = len(cipher)

    # Find the block size with the lowest normalized hamming distance between the first N blocks
    block_size: int = min(
        range(2, max_key_length),
        key=lambda block_size: average_hamming_distance(cipher, block_size, NUMBER_OF_BLOCKS)
    )

    # Split cipher up into blocks where each block $i contains the bytes from cipher at position $(i % block_size)
    cipher_blocks: Iterable[bytes] = (
        bytes(
            cipher[j]
            for j in range(i, cipher_length, block_size)
        )
        for i in range(block_size)
    )

    # Brute force each block as a single byte XOR cipher
    plaintext_blocks: List[bytes] = [
        brute_force_single_byte_xor([block])
        for block in cipher_blocks
    ]

    # Reconstruct the plaintext by placing all bytes back into the original order
    plaintext: bytes = bytes(
        plaintext_blocks[i % block_size][i // block_size]
        for i in range(cipher_length)
    )

    return plaintext
