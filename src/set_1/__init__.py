from base64 import b64encode
from string import ascii_letters, printable


def decode_hexidecimal(input: str) -> bytes:
    return bytes.fromhex(input)


def encode_base64(input: bytes) -> str:
    return b64encode(input).decode('utf-8')


def fixed_xor(input_a: bytes, input_b: bytes) -> bytes:
    if len(input_a) != len(input_b):
        raise Exception('Invalid operation')

    return bytes([
        a ^ b
        for a, b in zip(
            input_a,
            input_b
        )
    ])


def score(character: str) -> int:
    if character in ascii_letters:
        return 1
    elif character in printable:
        return 0
    else:
        return -1


def single_byte_xor_chiper(chiper: bytes) -> str:
    chiper_length = len(chiper)
    best_score = 0
    best_plain_text = None

    for character in ascii_letters:
        candidate_key = character.encode('utf-8') * chiper_length
        candidate_plain_text = fixed_xor(chiper, candidate_key).decode('utf-8')
        candidate_score = sum(score(character) for character in candidate_plain_text)

        if candidate_score > best_score:
            best_score = candidate_score
            best_plain_text = candidate_plain_text

    return best_plain_text
