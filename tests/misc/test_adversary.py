import pytest
from cryptopals.adversary import find_aes_ecb_cipher, brute_force_single_byte_xor
from cryptopals import Ciphertext


# Any test cases for adversary functions that are not covered by the cryptopal challenges
class TestMiscellaneousAdversary:

    def test_exception_short_text(self) -> None:
        # Very short plaintext can not be used to calculate hamming distance
        ciphertext: Ciphertext = Ciphertext.from_ascii('Hi')

        with pytest.raises(ValueError):
            find_aes_ecb_cipher([ciphertext])

    def test_exception_unprintable(self) -> None:
        # There does not exist a byte value that XORs this into a printable plaintext
        ciphertext: Ciphertext = Ciphertext(b'\x00\xff')

        with pytest.raises(ValueError):
            brute_force_single_byte_xor([ciphertext])
