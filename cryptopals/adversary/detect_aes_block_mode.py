from __future__ import annotations
from typing import List
from Crypto.Cipher import AES
from ..oracle import Oracle
from ..text import Ciphertext, Plaintext

# "Carefully" chosen input string for detecting AES ECB block mode
# The string contains an arbitrary character 64 times in a row
# After encrypting this plaintext with AES ECB mode, the cipher should have at least two repeated blocks of 16 bytes
AES_BLOCK_MODE_DETECTION_STRING: Plaintext = Plaintext.fixed_bytes(length=64)


# Function that detect whether a cipher was encrypted with either ECB or CBC block mode
def detect_aes_block_mode(oracle: Oracle) -> int:
    # Use the oracle function to encrypt our carefully chosen plaintext
    ciphertext: Ciphertext = oracle.encrypt(AES_BLOCK_MODE_DETECTION_STRING)

    # Convert to list in order to get the length
    blocks: List[bytes] = list(ciphertext.get_blocks())

    # Try to find two concecutive blocks which are idencital
    any_idencital_blocks: bool = any(
        ciphertext.get_block(block_index) == ciphertext.get_block(block_index + 1)
        for block_index in range(len(blocks) - 1)
    )

    return AES.MODE_ECB if any_idencital_blocks else AES.MODE_CBC
