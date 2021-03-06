from typing import Iterable, List, Dict, Tuple
from .detect_block_size import detect_block_size
from ..oracle import Oracle
from ..operation import get_block, nonrandom_bytes


def brute_force_ecb_unknown_string(oracle: Oracle) -> bytes:
    # Define types of all variables used in the for loop
    block_size: int
    unknown_string_length: int
    block_index: int
    prefix: bytes
    plaintext_values: Iterable[bytes]
    plaintext_cipher_pairs: Iterable[Tuple[bytes, bytes]]
    dictionary: Dict[bytes, int]
    cipher: bytes
    character: int

    # Starting with no known characters
    known_characters: bytearray = bytearray()

    block_size, unknown_string_length = detect_block_size(oracle)

    for byte_index in range(unknown_string_length):
        # Calculate the position of the block that will contain the byte with the current index
        block_index = (byte_index // block_size)

        # Pad our plaintext with a specific number of bytes ("0x00") in order to position
        # the next byte of the unknown string at the last byte of a block
        prefix = nonrandom_bytes((block_index + 1) * block_size - len(known_characters) - 1)

        # Create plaintext of the prefix followed by all known characters so far followed by each possible byte value
        # Here we iterate over the entire byte range 0-255; this could be reduced to string.printable
        plaintext_values = (
            prefix + known_characters + bytes([byte_value])
            for byte_value in range(256)
        )

        # Let the oracle encrypt each plaintext
        plaintext_cipher_pairs = (
            (plaintext, oracle.encrypt(plaintext))
            for plaintext in plaintext_values
        )

        # Store the first block of the cipher with the corresponding last byte
        dictionary = {
            get_block(cipher, block_index, block_size): plaintext[-1]
            for plaintext, cipher in plaintext_cipher_pairs
        }

        # Lookup the cipher of just the prefix and look it up in the dictionary
        # This will give us the value of one of the bytes of the unknown string
        cipher = oracle.encrypt(bytes(prefix))
        character = dictionary[get_block(cipher, block_index, block_size)]

        # Add the discovered character to the list of known characters so it can be used to dicover the next character
        known_characters.append(character)

    # Convert all characters from bytearray to bytes
    return bytes(known_characters)
