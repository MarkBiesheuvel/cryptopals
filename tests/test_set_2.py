import pytest
from cryptopals import aes, oracle, analyzer
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
    output: bytes = aes.encrypt_cbc_mode(input, key, iv)
    assert aes.decrypt_cbc_mode(output, key, iv) == input

    cipher: bytes = base64_to_bytes(''.join(file_iterator('tests/data/10.txt')))
    plaintext: bytes = funky_music()
    assert aes.decrypt_cbc_mode(cipher, key, iv) == plaintext


def test_challenge_11() -> None:
    # Already specify the types of the variables in the for-loop
    cipher: bytes
    actual_mode: aes.BlockCipherMode

    # Test 256 iterations since it is a random function
    for _ in range(256):
        # Let the encryption oracle encrypt our plaintext $AES_BLOCK_MODE_DETECTION_STRING
        cipher, actual_mode = oracle.random_block_mode(analyzer.AES_BLOCK_MODE_DETECTION_STRING)

        # Use analyzer to detect the mode
        assert analyzer.detect_aes_block_mode(cipher) == actual_mode


def test_challenge_12() -> None:
    plaintext: bytes = analyzer.brute_force_ecb_fixed_key_unknown_string(
        oracle.ecb_fixed_key_unknown_string
    )

    assert plaintext == b'R'
