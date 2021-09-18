from ..aes import BLOCK_SIZE
from ..operation import random_bytes


# Parent class for oracles
class Oracle:

    def __init__(self) -> None:
        # Pick a random 128-bit key (16 bytes)
        self.key: bytes = random_bytes(BLOCK_SIZE)

    def encrypt(self, plaintext: bytes) -> bytes:
        return plaintext
