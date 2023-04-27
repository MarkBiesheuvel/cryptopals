import pytest
from cryptopals.adversary import (
    find_aes_ecb_cipher,
    brute_force_single_byte_xor,
    brute_force_ecb_unknown_string,
)
from cryptopals.oracle import Oracle
from cryptopals import Ciphertext, Plaintext


class FakeOracle(Oracle):

    suffix = Plaintext.from_ascii('Hello, World!')

    def encrypt(self, plaintext: Plaintext) -> Ciphertext:
        # Append something at the end, so the brute_force_ecb_unknown_string adversary will try to find it.
        plaintext = (plaintext + self.suffix).pkcs7_pad()

        # Instead of encrypting data, return random data. (Meaning the suffix can not be brute forced)
        return Ciphertext.random_bytes(
            length=plaintext.length,
            block_size=plaintext.block_size
        )


# Any test cases for adversary functions that are not covered by the cryptopals challenges
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

    def test_exception_fake_oracle(self) -> None:
        # Creating an oracle that can not be brute forced (since it returns random data)
        oracle: FakeOracle = FakeOracle()

        # Encrypting with forbidden characters raises Exception
        with pytest.raises(IndexError):
            brute_force_ecb_unknown_string(oracle)
