from typing import Iterable, List, Tuple
from itertools import combinations
from ..text import Text

# Number of blocks to compare to eachother to find the most likely key length
# Higher number will be more accurate, but break on shorter ciphertexts
NUMBER_OF_BLOCKS: int = 6


# Not an adversary by itself, but used by both {brute_force_repeating_key_xor} and {find_aes_ecb_cipher}
def average_hamming_distance(ciphertext: Text, block_size: int) -> float:
    # This operation does not work if there are not enough blocks
    if (ciphertext.length / NUMBER_OF_BLOCKS) < block_size:
        raise Exception('Invalid operation')  # pragma: no cover

    # Adjust the block size to match the key length
    ciphertext.block_size = block_size

    # First $NUMBER_OF_BLOCKS blocks of size $block_size
    blocks: Iterable[Text] = (
        Text(ciphertext.get_block(block_index))
        for block_index in range(NUMBER_OF_BLOCKS)
    )

    # Combine each block with each other block
    combos: List[Tuple[Text, Text]] = list(combinations(blocks, 2))

    # Calculate the average hamming distance between blocks
    return sum(
        block_1.hamming_distance(block_2) / block_size
        for block_1, block_2 in combos
    ) / len(combos)
