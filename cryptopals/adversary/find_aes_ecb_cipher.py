from typing import Iterable
from ..aes import BLOCK_SIZE
from ..operation import average_hamming_distance

# Number of chunks to compare to eachother to guess the most likely ECB encrypted cipher
NUMBER_OF_BLOCKS: int = 6


# Function that detects the cipher which is most likely encrypted using ECB mode
def find_aes_ecb_cipher(ciphers: Iterable[bytes]) -> bytes:
    # Assumption: the plaintext is human-readable text, i.e. mostly alphanumeric characters
    # Therefore the hamming distance between characters is lower compared to random data
    # With ECB if blocks contain the same data, they will lead to the same result
    # So we are looking for a cipher with a low average hamming distance accros blocks
    return min(
        ciphers,
        key=lambda cipher: average_hamming_distance(cipher, BLOCK_SIZE, NUMBER_OF_BLOCKS)
    )
