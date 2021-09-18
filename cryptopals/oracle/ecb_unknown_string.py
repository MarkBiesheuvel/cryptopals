from .oracle import Oracle
from ..aes import encrypt_ebc_mode
from ..conversion import base64_to_bytes

# Given string by https://cryptopals.com/sets/2/challenges/12
UNKNOWN_STRING: bytes = base64_to_bytes(
    'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaG'
    'FpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0'
    'IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
)


class EcbUnknownStringOracle(Oracle):

    def __init__(self):
        super(EcbUnknownStringOracle, self).__init__()
        self.unknown_string = UNKNOWN_STRING

    def encrypt(self, plaintext: bytes) -> bytes:
        return encrypt_ebc_mode(plaintext + self.unknown_string, self.key)
