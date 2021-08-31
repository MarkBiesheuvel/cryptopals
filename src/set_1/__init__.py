from base64 import b64encode
from typing import Iterable
from math import inf
import string

CHARACTOR_ENCODING = 'utf-8'


# Function that convert a string with hexidecimal digits to bytes
# Challanges often give the input in this format, so this is used to convert that input
def decode_hexidecimal(input: str) -> bytes:
    return bytes.fromhex(input)


# Function that convert bytes to a base64 encoded string
def encode_base64(input: bytes) -> str:
    return b64encode(input).decode(CHARACTOR_ENCODING)


# Function that takes two equal-length bytes and produces their XOR combination
def fixed_xor(input_a: bytes, input_b: bytes) -> bytes:
    if len(input_a) != len(input_b):
        raise Exception('Invalid operation')

    # Python does not support bitwise operations on bytes, so we need to XOR byte-by-byte
    return bytes(a ^ b for a, b in zip(input_a, input_b))


def single_byte_xor(chiper: bytes, key: int) -> bytes:
    if key < 0 or 255 < key:
        raise Exception('Invalid operation')

    return bytes(byte ^ key for byte in chiper)


# Function to score a character with the likelyhood of it being part of a plain text string
def score(byte: int) -> float:
    character = chr(byte)

    # Lower case characters are common
    if character in string.ascii_lowercase:
        return 1.0
    # Upper case are common too, but too many might indicate an invalid string
    elif character in string.ascii_uppercase:
        return 0.8
    # Printable character such as whitespace and punctuation are acceptable, but should be uncommon
    elif character in string.printable:
        return 0.2
    # Unprintable characters disqualify the word
    else:
        return -inf


# Function to find the most likely plain text out of a iterator of candidates
def best_candidate(candidates: Iterable[bytes]) -> bytes:
    return max(
        candidates,
        key=lambda candidate: sum(score(character) for character in candidate)
    )


# Function that tries all one-byte keys against every chiper to find the most likely plain text
def single_byte_xor_chipers(ciphers: Iterable[bytes]) -> str:
    # Iterate over all one-byte values and try to XOR it with the chiper
    candidates = (
        single_byte_xor(cipher, byte)
        for cipher in ciphers
        for byte in range(256)
    )

    # Encode bytes as string
    return best_candidate(candidates).decode(CHARACTOR_ENCODING)
