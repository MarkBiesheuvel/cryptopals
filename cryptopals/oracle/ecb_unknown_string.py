from .oracle import Oracle
from ..text import Text
from ..operation import random_bytes

# Given string by https://cryptopals.com/sets/2/challenges/12
UNKNOWN_STRING: Text = Text.from_base64(
    'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaG'
    'FpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0'
    'IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
)


class EcbUnknownStringOracle(Oracle):

    def __init__(self, prefix_size: int = 0):
        super(EcbUnknownStringOracle, self).__init__()
        self.unknown_string: Text = UNKNOWN_STRING
        self.random_prefix: bytes = random_bytes(prefix_size)

    def encrypt(self, plaintext: Text) -> Text:
        # Prepend and append bytes to the given plaintext
        plaintext = Text(self.random_prefix + plaintext.to_bytes() + self.unknown_string.to_bytes())

        # Encrypt using AES EBC
        return plaintext.encrypt_ebc_mode(self.key)
