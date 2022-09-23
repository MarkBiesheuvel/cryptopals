from __future__ import annotations
from .parent import Text


# Type hint for a single block (used for keys of IVs)
# Provides garantuee that {self.block_size} == {self.length}
#
# NOTE: Both ciphertext and plaintext are both just a string of bytes.
#       However, here are two separate classes to provide better type hints throughout the code base.
class Block(Text):

    def __init__(self, value: bytes, /, *, block_size: int) -> None:
        length: int = len(value)

        if block_size != len(value):
            raise ValueError('Block size must be equal to length of block')

        super().__init__(value, block_size=block_size)
