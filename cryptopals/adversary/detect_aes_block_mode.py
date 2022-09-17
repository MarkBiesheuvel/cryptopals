from typing import List
from ..aes import BlockCipherMode
from ..oracle import Oracle
from ..text import Text

# "Carefully" chosen input string for detecting AES ECB block mode
# The string contains an arbitrary character 64 times in a row; in this case it's 64 times "0x55"
# After encrypting this plaintext with AES ECB mode, the cipher should have at least two repeated blocks of 16 bytes
AES_BLOCK_MODE_DETECTION_STRING: Text = Text(b'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU')


# Function that detect whether a cipher was encrypted with either ECB or CBC block mode
def detect_aes_block_mode(oracle: Oracle) -> BlockCipherMode:
    # Use the oracle function to encrypt our carefully chosen plaintext
    ciphertext: Text = oracle.encrypt(AES_BLOCK_MODE_DETECTION_STRING)

    blocks: List[bytes] = list(ciphertext.get_blocks())

    # Try to find two concecutive blocks which are idencital
    any_idencital_blocks: bool = any(
        ciphertext.get_block(block_index) == ciphertext.get_block(block_index + 1)
        for block_index in range(len(blocks) - 1)
    )

    return BlockCipherMode.ECB if any_idencital_blocks else BlockCipherMode.CBC
