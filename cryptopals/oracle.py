from random import choice, randint, randrange
from typing import Tuple
from .aes import encrypt_ebc_mode, encrypt_cbc_mode, BlockCipherMode, BLOCK_SIZE
from .conversion import base64_to_bytes


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


FIXED_KEY: bytes = random_bytes(BLOCK_SIZE)

UNKNOWN_STRING: bytes = base64_to_bytes(
    'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaG'
    'FpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0'
    'IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
)


def ecb_fixed_key_unknown_string(plaintext: bytes) -> bytes:
    return encrypt_ebc_mode(plaintext + UNKNOWN_STRING, FIXED_KEY)
