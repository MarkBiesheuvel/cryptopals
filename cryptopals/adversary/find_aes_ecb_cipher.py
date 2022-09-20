from typing import Iterable
from Crypto.Cipher import AES
from .average_hamming_distance import average_hamming_distance
from .. import Ciphertext


# Function that detects the cipher which is most likely encrypted using ECB mode
def find_aes_ecb_cipher(ciphertexts: Iterable[Ciphertext]) -> Ciphertext:
    # Assumption: the plaintext is human-readable text, i.e. mostly alphanumeric characters
    # Therefore the hamming distance between characters is lower compared to random data
    # With ECB if blocks contain the same data, they will lead to the same result
    # So we are looking for a cipher with a low average hamming distance accros blocks
    return min(
        ciphertexts,
        key=lambda ciphertext: average_hamming_distance(ciphertext)
    )
