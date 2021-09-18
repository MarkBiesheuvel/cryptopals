from typing import Iterable, List, Tuple
from random import randrange
from itertools import combinations


# Function that takes two equal-length bytes and produces their XOR combination
def fixed_xor(input_a: bytes, input_b: bytes) -> bytes:
    if len(input_a) != len(input_b):
        raise Exception('Invalid operation')

    # Python does not support bitwise operations on bytes, so we need to XOR byte-by-byte
    return bytes(a ^ b for a, b in zip(input_a, input_b))


def single_byte_xor(cipher: bytes, key: int) -> bytes:
    if key < 0 or 255 < key:
        raise Exception('Invalid operation')

    return bytes(byte ^ key for byte in cipher)


def repeating_key_xor(cipher: bytes, key: bytes) -> bytes:
    key_length: int = len(key)
    return bytes(byte ^ key[i % key_length] for (i, byte) in enumerate(cipher))


def pkcs7_pad(input: bytes, block_size: int) -> bytes:
    input_length: int = len(input)
    # Calculate the desired length based on the $block_size
    # After the padding the string should be longer, so we calculate how many times the $block_size fits in the input
    # and then add 1 extra block
    desired_length: int = (input_length // block_size + 1) * block_size
    difference: int = desired_length - input_length

    return bytes([
        input[i] if i < input_length else difference
        for i in range(desired_length)
    ])


def pkcs7_unpad(input: bytes) -> bytes:
    difference: int = input[-1]
    return input[:-difference]


def random_bytes(length: int) -> bytes:
    return bytes([randrange(256) for _ in range(length)])


def hamming_distance(input_a: bytes, input_b: bytes) -> int:
    # By computing the XOR, all bits that were different are 1, all bits that were the same are zero
    difference: bytes = fixed_xor(input_a, input_b)

    return sum(
        (byte >> i) & 1  # Count the bit if it is 1 (and thus was different)
        for byte in difference
        for i in range(8)  # Eight bits in a byte
    )


def average_hamming_distance(cipher: bytes, block_size: int, number_of_blocks: int) -> float:
    # This operation does not work if there are not enough blocks
    if len(cipher) / number_of_blocks < block_size:
        raise Exception('Invalid operation')

    # First $number_of_blocks blocks of size $block_size
    blocks: Iterable[bytes] = (cipher[i*block_size:(i+1)*block_size] for i in range(number_of_blocks))

    # Combine each block with each other block
    combos: List[Tuple[bytes, bytes]] = list(combinations(blocks, 2))

    # Calculate the average hamming distance between blocks
    return sum(
        hamming_distance(block_a, block_b) / block_size
        for block_a, block_b in combos
    ) / len(combos)
