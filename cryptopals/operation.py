from random import randrange

# The byte value of an arbitrary character to be used in building nonrandom plaintext
# The value 85 was chosen since it is alphanumeric character (U) and is 0101 0101 in binary
DEFAULT_CHARACTER: int = 85


def random_bytes(length: int) -> bytes:
    return bytes([randrange(256) for _ in range(length)])


def nonrandom_bytes(length: int) -> bytes:
    return bytes([DEFAULT_CHARACTER] * length)
