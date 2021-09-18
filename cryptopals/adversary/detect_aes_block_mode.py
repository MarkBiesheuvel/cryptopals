from typing import Callable
from ..aes import BlockCipherMode, BLOCK_SIZE

# "Carefully" chosen input string for detecting AES ECB block mode
# The string contains an arbitrary character 64 times in a row; in this case it's 64 times "0x55"
# After encrypting this plaintext with AES ECB mode, the cipher should have at least two repeated blocks of 16 bytes
AES_BLOCK_MODE_DETECTION_STRING: bytes = b'UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU'


# Function that detect whether a cipher was encrypted with either ECB or CBC block mode
def detect_aes_block_mode(encrypt: Callable[[bytes], bytes]) -> BlockCipherMode:
    # Use the oracle function to encrypt our carefully chosen plaintext
    cipher: bytes = encrypt(AES_BLOCK_MODE_DETECTION_STRING)

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
