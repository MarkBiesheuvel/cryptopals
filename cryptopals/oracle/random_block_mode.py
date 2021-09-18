from random import choice, randint
from .oracle import Oracle
from ..aes import encrypt_ebc_mode, encrypt_cbc_mode, BlockCipherMode, BLOCK_SIZE
from ..operation import random_bytes


class RandomBlockModeOracle(Oracle):

    def __init__(self) -> None:
        super(RandomBlockModeOracle, self).__init__()

        # Pick a mode at random
        self.mode: BlockCipherMode = choice([BlockCipherMode.ECB, BlockCipherMode.CBC])

        # Pick a prefix and postfix length at random
        self.prefix: bytes = random_bytes(randint(5, 100))
        self.postfix: bytes = random_bytes(randint(5, 100))

    def encrypt(self, plaintext: bytes) -> bytes:
        # Apply random prefix and postfix to the plaintext
        # This simulates the adversary having partial control over the input
        # For example, storing their username, which than is embeded in a json document and encrypted
        plaintext = self.prefix + plaintext + self.postfix

        cipher: bytes
        if self.mode == BlockCipherMode.ECB:
            cipher = encrypt_ebc_mode(plaintext, self.key)
        elif self.mode == BlockCipherMode.CBC:
            # Pick a random initialization vector
            iv: bytes = random_bytes(BLOCK_SIZE)

            cipher = encrypt_cbc_mode(plaintext, self.key, iv)
        else:
            raise Exception('Invalid operation')

        return cipher
