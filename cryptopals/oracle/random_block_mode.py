from random import choice, randint
from .oracle import Oracle
from ..aes import BlockCipherMode
from ..operation import random_bytes
from ..text import Text


class RandomBlockModeOracle(Oracle):

    def __init__(self) -> None:
        super(RandomBlockModeOracle, self).__init__()

        # Pick a mode at random
        self.mode: BlockCipherMode = choice([BlockCipherMode.ECB, BlockCipherMode.CBC])

        # Pick a prefix and postfix length at random
        self.prefix: bytes = random_bytes(randint(5, 100))
        self.postfix: bytes = random_bytes(randint(5, 100))

    def encrypt(self, plaintext: Text) -> Text:
        # Apply random prefix and postfix to the plaintext
        # This simulates the adversary having partial control over the input
        # For example, storing their username, which than is embeded in a json document and encrypted
        plaintext = Text(self.prefix + plaintext.to_bytes() + self.postfix)

        if self.mode == BlockCipherMode.ECB:
            return plaintext.encrypt_ebc_mode(self.key)

        elif self.mode == BlockCipherMode.CBC:
            # Pick a random initialization vector
            iv: bytes = random_bytes(plaintext.block_size)

            return plaintext.encrypt_cbc_mode(self.key, iv)

        else:
            raise Exception('Invalid operation')
