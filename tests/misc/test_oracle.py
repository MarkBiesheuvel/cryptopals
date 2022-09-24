import pytest
from cryptopals.oracle import Oracle, RandomBlockModeOracle, StructuredCookieOracle
from cryptopals import Plaintext


@pytest.fixture
def plaintext() -> Plaintext:
    return Plaintext.from_ascii('Hello, World!')


# Any test cases for Oracle class that are not covered by the cryptopal challenges
class TestMiscellaneousOracle:

    def test_exception_unimplemented_encrypt(self, plaintext: Plaintext) -> None:
        # Creating oracle is fine
        oracle: Oracle = Oracle()

        # Encrypting with unimplemented Oracle raises Exception
        with pytest.raises(NotImplementedError):
            oracle.encrypt(plaintext)

    def test_exception_invalid_aes_mode(self, plaintext: Plaintext) -> None:
        # Creating oracle is fine
        oracle: RandomBlockModeOracle = RandomBlockModeOracle()

        # Overriding the mode doesn't give an error, but shouldn't be done.
        oracle.mode = -1

        # Because encrypting with an invalid mode raises Exception
        with pytest.raises(ValueError):
            oracle.encrypt(plaintext)

    def test_exception_unprintable_email(self) -> None:
        # Creating oracle is fine
        oracle: StructuredCookieOracle = StructuredCookieOracle()

        # Create plaintext with unprintable characters
        plaintext: Plaintext = Plaintext(b'\x00')

        # Encrypting with unprintable characters raises Exception
        with pytest.raises(ValueError):
            oracle.encrypt(plaintext)

    def test_exception_forbidden_email(self) -> None:
        # Creating oracle is fine
        oracle: StructuredCookieOracle = StructuredCookieOracle()

        # Create plaintext with forbidden characters characters
        plaintext: Plaintext = Plaintext.from_ascii('admin=true')

        # Encrypting with forbidden characters raises Exception
        with pytest.raises(ValueError):
            oracle.encrypt(plaintext)
