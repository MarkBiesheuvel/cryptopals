from Crypto.Cipher import AES
from ..text import Text


# Parent class for oracles
class Oracle:

    def __init__(self) -> None:
        # Pick a random 128-bit key (16 bytes)
        self.key: Text = Text.random_bytes(
            length=AES.block_size,
            block_size=AES.block_size
        )

    def encrypt(self, plaintext: Text) -> Text:
        return plaintext  # pragma: no cover
