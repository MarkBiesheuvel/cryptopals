import pytest
from typing import Iterable
from src.set_1 import (
    decode_hexidecimal,
    encode_base64,
    fixed_xor,
    single_byte_xor_chipers
)


def file_iterator(filename: str) -> Iterable[str]:
    with open(filename, 'r') as file:
        while True:
            line = file.readline()
            if line == '':
                break
            else:
                yield line.strip()


def test_challenge_1() -> None:
    input: bytes = decode_hexidecimal(
        '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    )
    output: str = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert encode_base64(input) == output


def test_challenge_2() -> None:
    input_a: bytes = decode_hexidecimal('1c0111001f010100061a024b53535009181c')
    input_b: bytes = decode_hexidecimal('686974207468652062756c6c277320657965')
    output: bytes = decode_hexidecimal('746865206b696420646f6e277420706c6179')
    assert fixed_xor(input_a, input_b) == output


def test_challenge_3() -> None:
    cipher: bytes = decode_hexidecimal('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    assert single_byte_xor_chipers([cipher]) == 'Cooking MC\'s like a pound of bacon'


def test_challenge_4() -> None:
    ciphers: Iterable[bytes] = (
        decode_hexidecimal(line)
        for line in file_iterator('tests/data/4.txt')
    )
    assert single_byte_xor_chipers(ciphers) == 'Now that the party is jumping\n'
