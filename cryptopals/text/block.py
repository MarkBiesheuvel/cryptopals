from __future__ import annotations
from typing import Optional
from .parent import Text


# Type hint for a single block (used for keys of IVs)
# Provides garantuee that {self.block_size} == {self.length}
#
# NOTE: Both ciphertext and plaintext are both just a string of bytes.
#       However, here are two separate classes to provide better type hints throughout the code base.
class Block(Text):

    def __init__(self, value: bytes, /, *, block_size: Optional[int] = None):
        length: int = len(value)

        if block_size is None:
            block_size = len(value)  # pragma: no cover
        elif block_size != len(value):
            raise Exception('Block size must be equal to length of block')  # pragma: no cover

        super().__init__(value, block_size=block_size)
