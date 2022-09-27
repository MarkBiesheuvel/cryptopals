from typing import List
from ..oracle import Oracle
from .. import Ciphertext, Plaintext

# Using a bit-flip mask of 0b00001000 will turn ';' into '3' and '=' into '5' and vice versa
MASK: int = 0b00001000


def forge_admin_comment(oracle: Oracle) -> Ciphertext:
    # Try to be extra clever by entering user data that might bit-flip into the admin=true property
    # JOKE: this ciphertext is 3edgy5me (https://www.urbandictionary.com/define.php?term=3edgy5me)
    plaintext: Plaintext = Plaintext.from_ascii('3admin5true')

    # Encrypt as the oracle would normally do
    ciphertext: Ciphertext = oracle.encrypt(plaintext)

    # TODO: Calculate position of the start of our plaintext minus 1 block
    # Currently these numbers are based on pre-existing knowledge of the prefix length and block size
    byte_index: int = (32 - 16)

    # Bit flip the ciphertext in the correct places
    ciphertext_bytes: List[int] = list(ciphertext.to_bytes())
    ciphertext_bytes[byte_index + 0] ^= MASK
    ciphertext_bytes[byte_index + 6] ^= MASK

    # Fabricate a ciphertext with the bit flipped bytes
    return Ciphertext.from_iterable(ciphertext_bytes)
