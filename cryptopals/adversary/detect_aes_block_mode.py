from __future__ import annotations
from collections.abc import Iterable
from Crypto.Cipher import AES
from more_itertools import pairwise
from ..oracle import Oracle
from .. import Block, Ciphertext, Plaintext

# "Carefully" chosen input string for detecting AES ECB block mode
# The string contains an arbitrary character 64 times in a row
# After encrypting this plaintext with AES ECB mode, the cipher should have at least two repeated blocks of 16 bytes
AES_BLOCK_MODE_DETECTION_STRING: Plaintext = Plaintext.fixed_bytes(length=64)


# Function that detect whether a cipher was encrypted with either ECB or CBC block mode
def detect_aes_block_mode(oracle: Oracle) -> int:
    # Use the oracle function to encrypt our carefully chosen plaintext
    ciphertext: Ciphertext = oracle.encrypt(AES_BLOCK_MODE_DETECTION_STRING)

    # All blocks of cipher
    blocks: Iterable[Block] = ciphertext.get_blocks()

    # Combine each block with each other block
    combos: Iterable[tuple[Block, Block]] = pairwise(blocks)

    # Try to find two consecutive blocks which are identical
    any_identical_blocks: bool = any(block_1 == block_2 for block_1, block_2 in combos)

    return AES.MODE_ECB if any_identical_blocks else AES.MODE_CBC
