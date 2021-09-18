import pytest
from typing import Iterable
from cryptopals.aes import decrypt_ecb_mode
from cryptopals.adversary import brute_force_single_byte_xor, brute_force_repeating_key_xor, find_aes_ecb_cipher
from cryptopals.conversion import string_to_bytes, hexadecimal_to_bytes, base64_to_bytes
from cryptopals.operation import fixed_xor, repeating_key_xor, hamming_distance
from .helpers import file_iterator, funky_music


def test_challenge_1() -> None:
    input: bytes = hexadecimal_to_bytes(
        '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    )
    output: bytes = base64_to_bytes('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')
    assert input == output


def test_challenge_2() -> None:
    input_a: bytes = hexadecimal_to_bytes('1c0111001f010100061a024b53535009181c')
    input_b: bytes = hexadecimal_to_bytes('686974207468652062756c6c277320657965')
    output: bytes = hexadecimal_to_bytes('746865206b696420646f6e277420706c6179')
    assert fixed_xor(input_a, input_b) == output


def test_challenge_3() -> None:
    cipher: bytes = hexadecimal_to_bytes('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    plaintext: bytes = string_to_bytes('Cooking MC\'s like a pound of bacon')
    assert brute_force_single_byte_xor([cipher]) == plaintext


def test_challenge_4() -> None:
    ciphers: Iterable[bytes] = (
        hexadecimal_to_bytes(line)
        for line in file_iterator('tests/data/4.txt')
    )
    plaintext: bytes = string_to_bytes('Now that the party is jumping\n')
    assert brute_force_single_byte_xor(ciphers) == plaintext


def test_challenge_5() -> None:
    plaintext: bytes = string_to_bytes('Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal')
    key: bytes = string_to_bytes('ICE')
    cipher: bytes = hexadecimal_to_bytes(
        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    )
    assert repeating_key_xor(plaintext, key) == cipher


def test_challenge_6() -> None:
    input_a: bytes = string_to_bytes('this is a test')
    input_b: bytes = string_to_bytes('wokka wokka!!!')
    assert hamming_distance(input_a, input_b) == 37

    cipher: bytes = base64_to_bytes(''.join(file_iterator('tests/data/6.txt')))
    plaintext: bytes = funky_music()
    assert brute_force_repeating_key_xor(cipher, 40) == plaintext


def test_challenge_7() -> None:
    cipher: bytes = base64_to_bytes(''.join(file_iterator('tests/data/7.txt')))
    key: bytes = string_to_bytes('YELLOW SUBMARINE')
    plaintext: bytes = funky_music()
    assert decrypt_ecb_mode(cipher, key) == plaintext


def test_challenge_8() -> None:
    ciphers: Iterable[bytes] = (
        hexadecimal_to_bytes(line)
        for line in file_iterator('tests/data/8.txt')
    )
    ecb_cipher: bytes = hexadecimal_to_bytes(
        'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc'
        '06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd5664891'
        '54789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'
    )

    assert find_aes_ecb_cipher(ciphers) == ecb_cipher
