from cryptopals import Ciphertext, Plaintext
from cryptopals.adversary import brute_force_repeating_key_xor
from ..helpers import file_as_string, funky_music


class TestChallenge06:

    def test_hamming_distance(self) -> None:
        plaintext_1: Plaintext = Plaintext.from_ascii('this is a test')
        plaintext_2: Plaintext = Plaintext.from_ascii('wokka wokka!!!')

        assert plaintext_1.hamming_distance(plaintext_2) == 37

    def test_break_repeating_key_xor_cipher(self, funky_music: Plaintext) -> None:
        ciphertext: Ciphertext = Ciphertext.from_base64(file_as_string('../data/6.txt'))

        assert brute_force_repeating_key_xor(ciphertext, 40) == funky_music
