from typing import Iterable, List, Dict, Tuple
from .detect_block_size import detect_block_size
from ..oracle import Oracle

# The byte value of an arbitrary character to be used in building plaintext
DEFAULT_CHARACTER: int = 85


def brute_force_ecb_unknown_string(oracle: Oracle) -> bytes:
    # Define types of all variables used in the for loop
    block_size: int
    unknown_string_length: int
    block_offset: int
    prefix: List[int]
    plaintext_values: Iterable[bytes]
    plaintext_cipher_pairs: Iterable[Tuple[bytes, bytes]]
    dictionary: Dict[bytes, int]
    cipher: bytes
    character: int

    # Starting with no known characters
    known_characters: List[int] = []

    block_size, unknown_string_length = detect_block_size(oracle)

    for byte_index in range(unknown_string_length):
        # Calculate the position of the block that will contain the byte with the current index
        block_position = (byte_index // block_size) * block_size

        # Pad our plaintext with a specific number of bytes ("0x00") in order to position
        # the next byte of the unknown string at the last byte of a block
        prefix = [DEFAULT_CHARACTER] * (block_position + block_size - len(known_characters) - 1)

        # Create plaintext of the prefix followed by all known characters so far followed by each possible byte value
        # Here we iterate over the entire byte range 0-255; this could be reduced to string.printable
        plaintext_values = (
            bytes(prefix + known_characters + [byte_value])
            for byte_value in range(256)
        )

        # Let the oracle encrypt each plaintext
        plaintext_cipher_pairs = (
            (plaintext, oracle.encrypt(plaintext))
            for plaintext in plaintext_values
        )

        # Store the first block of the cipher with the corresponding last byte
        dictionary = {
            cipher[block_position:block_position+block_size]: plaintext[-1]
            for plaintext, cipher in plaintext_cipher_pairs
        }

        # Lookup the cipher of just the prefix and look it up in the dictionary
        # This will give us the value of one of the bytes of the unknown string
        cipher = oracle.encrypt(bytes(prefix))
        character = dictionary[cipher[block_position:block_position+block_size]]

        # Add the discovered character to the list of known characters so it can be used to dicover the next character
        known_characters.append(character)

    # Convert all characters into a byte array
    return bytes(known_characters)
