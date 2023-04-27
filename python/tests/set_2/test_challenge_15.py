import pytest
from cryptopals import Plaintext


@pytest.fixture
def plaintext() -> Plaintext:
    return Plaintext.from_ascii('ICE ICE BABY')


class TestChallenge15:

    # Verify correct padding
    def test_valid_padding(self, plaintext: Plaintext) -> None:
        assert Plaintext(b'ICE ICE BABY\x04\x04\x04\x04').pkcs7_unpad() == plaintext

    # Verify incorrect padding (mismatching byte value and number of bytes)
    def test_invalid_padding_mismatched_value(self, plaintext: Plaintext) -> None:
        with pytest.raises(Exception):
            Plaintext(b'ICE ICE BABY\x05\x05\x05\x05').pkcs7_unpad()

    # Verify incorrect padding (unequal byte values)
    def test_invalid_padding_unequal_values(self, plaintext: Plaintext) -> None:
        with pytest.raises(Exception):
            Plaintext(b'ICE ICE BABY\x01\x02\x03\x04').pkcs7_unpad()
