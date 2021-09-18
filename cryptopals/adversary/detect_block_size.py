from typing import Iterable, List, Dict, Tuple, Callable
from ..aes import BLOCK_SIZE

# The byte value of an arbitrary character to be used in building plaintext
DEFAULT_CHARACTER: int = 85


# Function that determines the block size of an encryption oracle by detecting when the padding jumps to the next block
def detect_block_size(encrypt: Callable[[bytes], bytes]) -> Tuple[int, int]:
    previous_length: int
    current_length: int
    plaintext: List[int] = []

    # Find the length of the cipher when encrypting with an empty plaintext
    current_length = len(encrypt(bytes(plaintext)))
    previous_length = current_length

    # Keep increasing the plaintext length until there is a jump in cipher length
    while previous_length == current_length:
        plaintext.append(DEFAULT_CHARACTER)
        previous_length = current_length
        current_length = len(encrypt(bytes(plaintext)))

    # The block size is equal to the job in cipher length, since we only added a single byte to the plaintext
    block_size: int = current_length - previous_length

    # Also calculate the length of the additional string that was appended or preppended to the plaintext
    # The plaintext plus additional string fit exactly in a cipher of the previous length, since the current length
    # needed an extra block of padding
    additional_string_length: int = previous_length - len(plaintext)

    return (block_size, additional_string_length)
