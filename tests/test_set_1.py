import pytest
from typing import Iterable
from cryptopals import Block, Ciphertext, Plaintext
from cryptopals.adversary import brute_force_single_byte_xor, brute_force_repeating_key_xor, find_aes_ecb_cipher
from .helpers import file_iterator, file_as_string, funky_music


def test_challenge_01() -> None:
    plaintext_1: Plaintext = Plaintext.from_hexadecimal(
        '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    )
    plaintext_2: Plaintext = Plaintext.from_base64('SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')

    assert plaintext_1 == plaintext_2


def test_challenge_02() -> None:
    plaintext_1: Plaintext = Plaintext.from_hexadecimal('1c0111001f010100061a024b53535009181c')
    plaintext_2: Plaintext = Plaintext.from_hexadecimal('686974207468652062756c6c277320657965')
    ciphertext: Ciphertext = Ciphertext.from_hexadecimal('746865206b696420646f6e277420706c6179')

    assert plaintext_1.fixed_xor(plaintext_2, target_class=Ciphertext) == ciphertext


def test_challenge_03() -> None:
    ciphertext: Ciphertext = Ciphertext.from_hexadecimal(
        '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    )
    plaintext: Plaintext = Plaintext.from_ascii('Cooking MC\'s like a pound of bacon')

    assert brute_force_single_byte_xor([ciphertext]) == plaintext


def test_challenge_04() -> None:
    ciphertexts: Iterable[Ciphertext] = (
        Ciphertext.from_hexadecimal(line)
        for line in file_iterator('tests/data/4.txt')
    )
    plaintext: Plaintext = Plaintext.from_ascii('Now that the party is jumping\n')

    assert brute_force_single_byte_xor(ciphertexts) == plaintext


def test_challenge_05() -> None:
    key: bytes = b'ICE'
    plaintext: Plaintext = Plaintext.from_ascii(
        'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
    )
    ciphertext: Ciphertext = Ciphertext.from_hexadecimal(
        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    )

    assert plaintext.repeating_key_xor(key, target_class=Ciphertext) == ciphertext


def test_challenge_06(funky_music: Plaintext) -> None:
    plaintext_1: Plaintext = Plaintext.from_ascii('this is a test')
    plaintext_2: Plaintext = Plaintext.from_ascii('wokka wokka!!!')

    assert plaintext_1.hamming_distance(plaintext_2) == 37

    ciphertext: Ciphertext = Ciphertext.from_base64(file_as_string('tests/data/6.txt'))

    assert brute_force_repeating_key_xor(ciphertext, 40) == funky_music


def test_challenge_07(funky_music: Plaintext) -> None:
    key: Block = Block.from_ascii('YELLOW SUBMARINE')
    ciphertext: Ciphertext = Ciphertext.from_base64(file_as_string('tests/data/7.txt'))

    assert ciphertext.decrypt_ecb_mode(key) == funky_music


def test_challenge_08() -> None:
    ciphertexts: Iterable[Ciphertext] = (
        Ciphertext.from_hexadecimal(line)
        for line in file_iterator('tests/data/8.txt')
    )
    ecb_ciphertext: Ciphertext = Ciphertext.from_hexadecimal(
        'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc'
        '06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd5664891'
        '54789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'
    )

    assert find_aes_ecb_cipher(ciphertexts) == ecb_ciphertext
