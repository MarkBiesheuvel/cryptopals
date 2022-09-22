import pytest
from cryptopals import Block, Ciphertext, Plaintext
from ..helpers import file_as_string, funky_music


@pytest.fixture
def key() -> Block:
    return Block.from_ascii('YELLOW SUBMARINE')


@pytest.fixture
def iv(key: Block) -> Block:
    return Block.fixed_bytes(
        length=key.length,
        block_size=key.length,
        fixed_byte=0
    )


class TestChallenge10:

    def test_aes_encrypt_in_cbc_mode(self, key: Block, iv: Block) -> None:
        plaintext: Plaintext = Plaintext.from_ascii('Hello, World!')
        ciphertext: Ciphertext = plaintext.encrypt_cbc_mode(key, iv)

        assert ciphertext.decrypt_cbc_mode(key, iv) == plaintext

    def test_aes_decrypt_in_cbc_mode(self, key: Block, iv: Block, funky_music: Plaintext) -> None:
        ciphertext: Ciphertext = Ciphertext.from_base64(file_as_string('tests/data/10.txt'))

        assert ciphertext.decrypt_cbc_mode(key, iv) == funky_music
