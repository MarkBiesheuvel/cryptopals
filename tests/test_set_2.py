import pytest
from cryptopals import *


def test_challenge_9() -> None:
    input: bytes = string_to_bytes('YELLOW SUBMARINE')
    assert pkcs7_padding(input, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'
    assert pkcs7_padding(input, 18) == b'YELLOW SUBMARINE\x02\x02'
    assert pkcs7_padding(input, 31) == b'YELLOW SUBMARINE\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
