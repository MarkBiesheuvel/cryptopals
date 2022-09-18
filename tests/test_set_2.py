import pytest
from typing import Dict
from cryptopals.adversary import detect_aes_block_mode, brute_force_ecb_unknown_string, forge_admin_profile
from cryptopals.oracle import RandomBlockModeOracle, EcbUnknownStringOracle, StructuredCookieOracle
from cryptopals.text import Text
from .helpers import file_iterator, file_as_string, funky_music


def test_challenge_09() -> None:
    yellow_submarine = 'YELLOW SUBMARINE'

    assert Text.from_ascii(yellow_submarine, block_size=20).pkcs7_pad() == \
        Text(b'YELLOW SUBMARINE\x04\x04\x04\x04')

    assert Text.from_ascii(yellow_submarine, block_size=31).pkcs7_pad() == \
        Text(b'YELLOW SUBMARINE\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f')

    assert Text.from_ascii(yellow_submarine, block_size=16).pkcs7_pad() == \
        Text(b'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10')


def test_challenge_10() -> None:
    plaintext_1: Text = Text.from_ascii('Hello, World!')
    key: Text = Text.from_ascii('YELLOW SUBMARINE')
    iv: Text = Text.fixed_bytes(
        length=key.length,
        block_size=key.length,
        fixed_byte=0
    )

    ciphertext_1: Text = plaintext_1.encrypt_cbc_mode(key, iv)

    assert ciphertext_1.decrypt_cbc_mode(key, iv) == plaintext_1

    ciphertext_2: Text = Text.from_base64(file_as_string('tests/data/10.txt'))
    plaintext_2: Text = funky_music()

    assert ciphertext_2.decrypt_cbc_mode(key, iv) == plaintext_2


def test_challenge_11() -> None:
    # Test 256 iterations since it is a random function
    for _ in range(256):
        # Initialize a new oracle to get a new random mode and random key
        oracle: RandomBlockModeOracle = RandomBlockModeOracle()

        # Use analyzer to detect the mode
        assert detect_aes_block_mode(oracle) == oracle.mode


def test_challenge_12() -> None:
    oracle: EcbUnknownStringOracle = EcbUnknownStringOracle()
    assert brute_force_ecb_unknown_string(oracle) == oracle.unknown_string


def test_challenge_13() -> None:
    oracle: StructuredCookieOracle = StructuredCookieOracle()
    ciphertext: Text = forge_admin_profile(oracle)

    forged_profile: Dict[str, str] = oracle.decrypt(ciphertext)
    assert forged_profile['role'] == 'admin'


def test_challenge_14() -> None:
    # TODO: variable length prefix
    oracle: EcbUnknownStringOracle = EcbUnknownStringOracle(prefix_size=4)
    assert brute_force_ecb_unknown_string(oracle) == oracle.unknown_string
