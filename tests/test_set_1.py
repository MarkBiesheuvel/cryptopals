import pytest
from src.set_1 import decode_hexidecimal, encode_base64, fixed_xor, single_byte_xor_chiper


def test_challenge_1():
    input = decode_hexidecimal(
        '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    )
    output = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert encode_base64(input) == output


def test_challenge_2():
    a = decode_hexidecimal('1c0111001f010100061a024b53535009181c')
    b = decode_hexidecimal('686974207468652062756c6c277320657965')
    output = decode_hexidecimal('746865206b696420646f6e277420706c6179')
    assert fixed_xor(a, b) == output


def test_challenge_3():
    chiper = decode_hexidecimal('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    assert single_byte_xor_chiper(chiper) == 'Cooking MC\'s like a pound of bacon'
