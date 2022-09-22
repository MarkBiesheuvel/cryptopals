from cryptopals import Ciphertext, Plaintext
from cryptopals.adversary import brute_force_single_byte_xor


class TestChallenge03:

    def test_break_single_byte_xor_cipher(self) -> None:
        ciphertext: Ciphertext = Ciphertext.from_hexadecimal(
            '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        )
        plaintext: Plaintext = Plaintext.from_ascii('Cooking MC\'s like a pound of bacon')

        assert brute_force_single_byte_xor([ciphertext]) == plaintext
