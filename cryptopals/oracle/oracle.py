from Crypto.Cipher import AES
from ..operation import random_bytes
from ..text import Text


# Parent class for oracles
class Oracle:

    def __init__(self) -> None:
        # Pick a random 128-bit key (16 bytes)
        self.key: bytes = random_bytes(AES.block_size)

    def encrypt(self, plaintext: Text) -> Text:
        return plaintext
