from typing import Iterable
from math import inf
from string import ascii_lowercase, ascii_uppercase, printable
from .operations import single_byte_xor


# Function to score a character with the likelyhood of it being part of a plain text string
def score(byte: int) -> float:
    character: str = chr(byte)

    # Lower case characters are common
    if character in ascii_lowercase:
        return 1.0
    # Upper case are common too, but too many might indicate an invalid string
    elif character in ascii_uppercase:
        return 0.8
    # Printable character such as whitespace and punctuation are acceptable, but should be uncommon
    elif character in printable:
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
def single_byte_xor_chipers(ciphers: Iterable[bytes]) -> bytes:
    # Iterate over all one-byte values and try to XOR it with the chiper
    candidates: Iterable[bytes] = (
        single_byte_xor(cipher, byte)
        for cipher in ciphers
        for byte in range(256)
    )

    # Encode bytes as string
    return best_candidate(candidates)
