import pytest
from typing import Iterable
from cryptopals import (
    bytes_to_string,
    string_to_bytes,
    hexadecimal_to_bytes,
    bytes_to_base64,
    fixed_xor,
    repeating_key_xor,
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
    input: bytes = hexadecimal_to_bytes(
        '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    )
    output: str = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert bytes_to_base64(input) == output


def test_challenge_2() -> None:
    input_a: bytes = hexadecimal_to_bytes('1c0111001f010100061a024b53535009181c')
    input_b: bytes = hexadecimal_to_bytes('686974207468652062756c6c277320657965')
    output: bytes = hexadecimal_to_bytes('746865206b696420646f6e277420706c6179')
    assert fixed_xor(input_a, input_b) == output


def test_challenge_3() -> None:
    cipher: bytes = hexadecimal_to_bytes('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    output: str = 'Cooking MC\'s like a pound of bacon'
    assert bytes_to_string(single_byte_xor_chipers([cipher])) == output


def test_challenge_4() -> None:
    ciphers: Iterable[bytes] = (
        hexadecimal_to_bytes(line)
        for line in file_iterator('tests/data/4.txt')
    )
    output = 'Now that the party is jumping\n'
    assert bytes_to_string(single_byte_xor_chipers(ciphers)) == output


def test_challenge_5() -> None:
    plain_text = string_to_bytes('Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal')
    key = string_to_bytes('ICE')
    output = hexadecimal_to_bytes(
        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    )

    assert repeating_key_xor(plain_text, key) == output
