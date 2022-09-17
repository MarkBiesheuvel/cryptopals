from typing import Iterable, List, Dict, Tuple
from .detect_block_size import detect_block_size
from ..oracle import Oracle
from ..operation import get_block, nonrandom_bytes

# List of printable ASCII charactors
PRINTABLE_CHARACTERS = list(range(9, 13)) + list(range(32, 126))


def detect_prepended_string_length(oracle, block_size) -> int:
    offset: int = block_size
    next_block: bytes = get_block(oracle.encrypt(nonrandom_bytes(offset)), 0, block_size)

    # As long as (prepended_string_length + offset) is larger than a single block,
    # the first block will always be indentical.
    # Keep reducing the offset until the first block of the cipher is different to find prepended_string_length
    while True:
        current_block = next_block
        next_block = get_block(oracle.encrypt(nonrandom_bytes(offset - 1)), 0, block_size)

        if next_block == current_block:
            offset -= 1
        else:
            break

    return block_size - offset


def brute_force_ecb_unknown_string(oracle: Oracle) -> bytes:
    # Starting with no known characters
    known_characters: bytearray = bytearray()

    # Detect the block size and determine how many extra bytes the oracle produces
    block_size, additional_string_length = detect_block_size(oracle)

    # Calculate offset to align the next unknown byte in the last position of a block
    prepended_string_length: int = detect_prepended_string_length(oracle, block_size)

    # Brute force each character of the unknown string one by one
    for i in range(additional_string_length - prepended_string_length):

        # The prepended string increases the index (within the plaintext/cipher) of the character we are looking for
        byte_index: int = i + prepended_string_length

        # Calculate the block number within the plaintext/cipher which will contain the character we are looking for
        block_index: int = (byte_index // block_size)

        # Prefix all plaintexts with a specific number of bytes to position
        # the character we are looking for in the last position of the block
        prefix: bytes = nonrandom_bytes((block_index + 1) * block_size - byte_index - 1)

        # Create plaintexts from the prefix, followed by all known characters, followed by each printable byte value
        plaintext_values: Iterable[bytes] = (
            prefix + known_characters + bytes([byte_value])
            for byte_value in PRINTABLE_CHARACTERS
        )

        # Let the oracle encrypt each plaintext with the format
        plaintext_cipher_pairs: Iterable[Tuple[bytes, bytes]] = (
            (plaintext, oracle.encrypt(plaintext))
            for plaintext in plaintext_values
        )

        # Store the block of the cipher containing the different bytes values in the last position
        dictionary: Dict[bytes, int] = {
            get_block(cipher, block_index, block_size): plaintext[-1]
            for plaintext, cipher in plaintext_cipher_pairs
        }

        # Encrypt only the prefix and lookup the block in the dictionary
        #
        # Visualization: block size is 4, unknown string has 5 characters of which 2 are known, byte is X
        # 0000 [0kkX] kkuu u
        # 0000 [0kku] uu
        cipher: bytes = oracle.encrypt(bytes(prefix))
        block: bytes = get_block(cipher, block_index, block_size)

        # Add the discovered character to the list of known characters so it can be used in the next step
        if block in dictionary:
            character: int = dictionary[block]
            known_characters.append(character)
        else:
            raise Exception('Unable to detect charachter')

    # Convert from bytesarray to bytes
    return bytes(known_characters)
