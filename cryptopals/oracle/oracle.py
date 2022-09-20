from Crypto.Cipher import AES
from ..text import Block, Ciphertext, Plaintext


# Parent class for oracles
class Oracle:

    def __init__(self) -> None:
        # Pick a random 128-bit key (16 bytes)
        self.key: Block = Block.random_bytes(
            length=AES.block_size,
            block_size=AES.block_size
        )

    def encrypt(self, plaintext: Plaintext) -> Ciphertext:
        return Ciphertext(plaintext.to_bytes())  # pragma: no cover
