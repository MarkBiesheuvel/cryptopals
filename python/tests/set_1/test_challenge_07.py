from cryptopals import Block, Ciphertext, Plaintext
from ..helpers import file_as_string, funky_music


class TestChallenge07:

    def test_aes_decrypt_in_ecb_mode(self, funky_music: Plaintext) -> None:
        key: Block = Block.from_ascii('YELLOW SUBMARINE')
        ciphertext: Ciphertext = Ciphertext.from_base64(file_as_string('../data/7.txt'))

        assert ciphertext.decrypt_ecb_mode(key) == funky_music
