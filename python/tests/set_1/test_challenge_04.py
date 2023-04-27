from collections.abc import Iterable
from cryptopals import Ciphertext, Plaintext
from cryptopals.adversary import brute_force_single_byte_xor
from ..helpers import file_iterator


class TestChallenge04:

    def test_detect_single_byte_xor_cipher(self) -> None:
        ciphertexts: Iterable[Ciphertext] = (
            Ciphertext.from_hexadecimal(line)
            for line in file_iterator('tests/data/4.txt')
        )
        plaintext: Plaintext = Plaintext.from_ascii('Now that the party is jumping\n')

        assert brute_force_single_byte_xor(ciphertexts) == plaintext
