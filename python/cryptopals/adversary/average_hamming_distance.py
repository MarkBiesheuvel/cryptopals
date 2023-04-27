from collections.abc import Iterable
from itertools import combinations
from .. import Text, Block

# Number of blocks to compare to each other to find the most likely key length
# Higher number will be more accurate, but break on shorter ciphertexts
NUMBER_OF_BLOCKS: int = 6


# Not an adversary by itself, but used by both {brute_force_repeating_key_xor} and {find_aes_ecb_cipher}
def average_hamming_distance(text: Text) -> float:
    # This operation does not work if there are not enough blocks
    if (text.length / NUMBER_OF_BLOCKS) < text.block_size:
        raise ValueError('Invalid operation')

    # First {NUMBER_OF_BLOCKS} blocks of size {text.block_size}
    blocks: Iterable[Block] = (
        text.get_block(block_index)
        for block_index in range(NUMBER_OF_BLOCKS)
    )

    # Combine each block with each other block
    combos: list[tuple[Block, Block]] = list(combinations(blocks, 2))

    # Calculate the average hamming distance between blocks
    return sum(
        block_1.hamming_distance(block_2) / text.block_size
        for block_1, block_2 in combos
    ) / len(combos)
