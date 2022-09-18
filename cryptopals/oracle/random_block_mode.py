from Crypto.Cipher import AES
from random import choice, randint
from .oracle import Oracle
from ..text import Text


class RandomBlockModeOracle(Oracle):

    def __init__(self) -> None:
        super(RandomBlockModeOracle, self).__init__()

        # Pick a mode at random
        self.mode: int = choice([AES.MODE_ECB, AES.MODE_CBC])

        # Pick a prefix and postfix length at random
        self.prefix: Text = Text.random_bytes(length=randint(5, 100))
        self.postfix: Text = Text.random_bytes(length=randint(5, 100))

    def encrypt(self, plaintext: Text) -> Text:
        # Apply random prefix and postfix to the plaintext
        # This simulates the adversary having partial control over the input
        # For example, storing their username, which than is embeded in a json document and encrypted
        plaintext = (self.prefix + plaintext + self.postfix)

        if self.mode == AES.MODE_ECB:
            return plaintext.encrypt_ebc_mode(self.key)

        elif self.mode == AES.MODE_CBC:
            # Pick a random initialization vector
            iv: Text = Text.random_bytes(length=plaintext.block_size)

            return plaintext.encrypt_cbc_mode(self.key, iv)

        else:
            raise Exception('Invalid operation')  # pragma: no cover
