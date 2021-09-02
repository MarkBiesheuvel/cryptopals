import pytest
from cryptopals import *
from .helpers import file_iterator


def test_challenge_9() -> None:
    input: bytes = string_to_bytes('YELLOW SUBMARINE')
    assert pkcs7_pad(input, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04'
    assert pkcs7_pad(input, 31) == b'YELLOW SUBMARINE\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'
    assert pkcs7_pad(input, 16) == b'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'


def test_challenge_10() -> None:
    input: bytes = string_to_bytes('Hello, World!')
    key: bytes = string_to_bytes('YELLOW SUBMARINE')
    iv: bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    output: bytes = aes_cbc_encrypt(input, key, iv)
    assert aes_cbc_decrypt(output, key, iv) == input

    cipher: bytes = base64_to_bytes(''.join(file_iterator('tests/data/10.txt')))
    plain_text: str = bytes_to_string(aes_cbc_decrypt(cipher, key, iv))
    assert 'Play that funky music' in plain_text
    assert 'I\'m back and I\'m ringin\' the bell' in plain_text
    assert 'Well that\'s my DJ Deshay cuttin\' all them Z\'s' in plain_text


def test_challenge_11() -> None:
    # Already specify the types of the variables in the for-loop
    cipher: bytes
    actual_mode: BlockCipherMode
    detected_mode: BlockCipherMode

    # Test 256 iterations since it is a random function
    for _ in range(256):
        # Let the encryption oracle encrypt our $plain_text
        cipher, actual_mode = encryption_oracle(AES_BLOCK_MODE_DETECTION_STRING)

        # Use analyzer to detect the mode
        detected_mode = detect_aes_block_mode(cipher)
        assert detected_mode == actual_mode
