from typing import Iterable, List, Dict, Tuple
from .detect_block_size import detect_block_size
from ..oracle import Oracle
from .. import Block, Ciphertext, Plaintext

# List of printable ASCII charactors
PRINTABLE_CHARACTERS = list(range(9, 13)) + list(range(32, 126))


# Initialize a text with only a single byte
def single_byte(byte_value: int, block_size: int) -> Plaintext:
    return Plaintext.from_iterable(
        [byte_value],
        block_size=block_size
    )


# Get the first block of the cipher given a plaintext of {plaintext_length}
def get_first_cipher_block_for_plaintext_length(oracle: Oracle, plaintext_length: int, block_size: int) -> Block:
    plaintext: Plaintext = Plaintext.fixed_bytes(
        length=plaintext_length,
        block_size=block_size
    )

    return oracle.encrypt(plaintext).get_block(0)


def detect_prepended_string_length(oracle: Oracle, block_size: int) -> int:
    plaintext_length: int = block_size
    current_block: Block
    next_block: Block = get_first_cipher_block_for_plaintext_length(oracle, plaintext_length, block_size)

    # As long as ({prepended_string_length} + {plaintext_length}) is larger than a single block,
    # the first block will always be indentical.
    # Keep reducing {plaintext_length} until the first block of the cipher is different to find prepended_string_length
    #
    # NOTE: Assuming {prepended_string_length} < {block_size}
    while True:
        current_block = next_block
        next_block = get_first_cipher_block_for_plaintext_length(oracle, plaintext_length - 1, block_size)

        if next_block == current_block:
            plaintext_length -= 1
        else:
            break

    return block_size - plaintext_length


def brute_force_ecb_unknown_string(oracle: Oracle) -> Plaintext:
    # Detect the block size and determine how many extra bytes the oracle produces
    block_size: int
    additional_string_length: int
    block_size, additional_string_length = detect_block_size(oracle)

    # Starting with no known characters
    known_characters: Plaintext = Plaintext.from_iterable([], block_size=block_size)

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
        prefix: Plaintext = Plaintext.fixed_bytes(
            length=(block_index + 1) * block_size - byte_index - 1,
            block_size=block_size
        )

        # Create plaintexts from the prefix, followed by all known characters, followed by each printable byte value
        plaintexts: Dict[int, Plaintext] = {
            byte_value: (prefix + known_characters + single_byte(byte_value, block_size))
            for byte_value in PRINTABLE_CHARACTERS
        }

        # Store the block of the cipher containing the different bytes values in the last position
        blocks: Dict[Block, int] = {
            oracle.encrypt(plaintext).get_block(block_index): byte_value
            for byte_value, plaintext in plaintexts.items()
        }

        # Encrypt only the prefix and lookup the block in the dictionary
        #
        # Visualization: block size is 4, unknown string has 5 characters of which 2 are known, byte is X
        # 0000 [0kkX] kkuu u
        # 0000 [0kku] uu
        block: Block = oracle.encrypt(prefix).get_block(block_index)

        # Add the discovered character to the list of known characters so it can be used in the next step
        if block in blocks:
            character: int = blocks[block]
            known_characters += character
        else:
            raise Exception('Unable to detect charachter')  # pragma: no cover

    # Convert from bytesarray to bytes
    return known_characters
