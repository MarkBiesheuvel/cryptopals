from typing import List, Tuple
from ..oracle import Oracle
from .. import Ciphertext, Plaintext


def ciphertext_length(oracle: Oracle, plaintext_length: int) -> int:
    plaintext: Plaintext = Plaintext.fixed_bytes(length=plaintext_length)
    ciphertext: Ciphertext = oracle.encrypt(plaintext)
    return ciphertext.length


# Function that determines the block size of an encryption oracle by detecting when the padding jumps to the next block
def detect_block_size(oracle: Oracle) -> Tuple[int, int]:
    # Initialize all variables before entering the while loop
    plaintext_length: int = 0
    previous_cipher_length: int
    current_cipher_length: int
    previous_cipher_length = current_cipher_length = ciphertext_length(oracle, plaintext_length)

    # Keep increasing the plaintext length until there is a jump in cipher length
    while previous_cipher_length == current_cipher_length:
        # Increment the plaintext length by 1
        plaintext_length += 1

        # Retrieve the cipher from the oracle
        previous_cipher_length = current_cipher_length
        current_cipher_length = ciphertext_length(oracle, plaintext_length)

    # The block size is equal to the job in cipher length, since we only added a single byte to the plaintext
    block_size: int = current_cipher_length - previous_cipher_length

    # Also calculate the length of the additional string that was appended or prepended to the plaintext
    # The plaintext plus additional string fit exactly in a cipher of the previous length, since the current length
    # needed an extra block of padding
    additional_string_length: int = previous_cipher_length - plaintext_length

    return (block_size, additional_string_length)
