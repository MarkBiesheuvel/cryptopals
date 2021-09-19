import pytest
from typing import Dict
from cryptopals.aes import encrypt_cbc_mode, decrypt_cbc_mode, BlockCipherMode
from cryptopals.adversary import detect_aes_block_mode, brute_force_ecb_unknown_string, forge_admin_profile
from cryptopals.oracle import RandomBlockModeOracle, EcbUnknownStringOracle, StructuredCookieOracle
from cryptopals.conversion import string_to_bytes, bytes_to_string, base64_to_bytes
from cryptopals.operation import pkcs7_pad
from .helpers import file_iterator, funky_music


def test_challenge_9() -> None:
    input: bytes = string_to_bytes('YELLOW SUBMARINE')
    assert pkcs7_pad(input, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'
    assert pkcs7_pad(input, 31) == b'YELLOW SUBMARINE\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
    assert pkcs7_pad(input, 16) == b'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'


def test_challenge_10() -> None:
    input: bytes = string_to_bytes('Hello, World!')
    key: bytes = string_to_bytes('YELLOW SUBMARINE')
    iv: bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    output: bytes = encrypt_cbc_mode(input, key, iv)
    assert decrypt_cbc_mode(output, key, iv) == input

    cipher: bytes = base64_to_bytes(''.join(file_iterator('tests/data/10.txt')))
    plaintext: bytes = funky_music()
    assert decrypt_cbc_mode(cipher, key, iv) == plaintext


def test_challenge_11() -> None:
    # Already specify the types of the variables in the for-loop
    oracle: RandomBlockModeOracle
    cipher: bytes
    actual_mode: BlockCipherMode

    # Test 256 iterations since it is a random function
    for _ in range(256):
        # Initialize a new oracle to get a new random mode and random key
        oracle = RandomBlockModeOracle()

        # Use analyzer to detect the mode
        assert detect_aes_block_mode(oracle) == oracle.mode


def test_challenge_12() -> None:
    oracle: EcbUnknownStringOracle = EcbUnknownStringOracle()
    assert brute_force_ecb_unknown_string(oracle) == oracle.unknown_string


def test_challenge_13() -> None:
    role: bytes = string_to_bytes('role')
    admin: bytes = string_to_bytes('admin')

    oracle: StructuredCookieOracle = StructuredCookieOracle()
    cipher: bytes = forge_admin_profile(oracle)

    assert oracle.decrypt(cipher)[role] == admin
