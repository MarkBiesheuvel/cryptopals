from random import choice, randint, randrange
from typing import Tuple
from .aes import encrypt_ebc_mode, encrypt_cbc_mode, BlockCipherMode, BLOCK_SIZE


def random_bytes(length: int) -> bytes:
    return bytes([randrange(256) for _ in range(length)])


def random_block_mode(plaintext: bytes) -> Tuple[bytes, BlockCipherMode]:
    # Pick a mode at random
    mode: BlockCipherMode = choice([BlockCipherMode.ECB, BlockCipherMode.CBC])

    # Pick a random 128-bit key (16 bytes)
    key: bytes = random_bytes(BLOCK_SIZE)

    # Pick a prefix and postfix length at random
    prefix: bytes = random_bytes(randint(5, 100))
    postfix: bytes = random_bytes(randint(5, 100))

    # Apply random prefix and postfix to the plaintext
    # This simulates the adversary having partial control over the input
    # For example, storing their username, which than is embeded in a json document and encrypted
    plaintext = prefix + plaintext + postfix

    cipher: bytes
    if mode == BlockCipherMode.ECB:
        cipher = encrypt_ebc_mode(plaintext, key)
    elif mode == BlockCipherMode.CBC:
        # Pick a random initialization vector
        iv: bytes = random_bytes(BLOCK_SIZE)

        cipher = encrypt_cbc_mode(plaintext, key, iv)
    else:
        raise Exception('Invalid operation')

    return (cipher, mode)
