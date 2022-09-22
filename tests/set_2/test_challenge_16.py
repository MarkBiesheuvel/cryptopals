import pytest
from typing import Dict
from cryptopals import Plaintext
from cryptopals.oracle import CommentsOracle


@pytest.fixture
def oracle() -> CommentsOracle:
    return CommentsOracle()


class TestChallenge16:

    def test_cannot_break_by_userdata(self, oracle: CommentsOracle) -> None:
        # Try to be clever by entering userdata that might add the admin=true property
        plaintext: Plaintext = Plaintext.from_ascii(';admin=true')

        # Encrypt and decrypt as the oracle would normally do
        properties: Dict[str, str] = oracle.decrypt(oracle.encrypt(plaintext))

        # The admin property should not be set since the userdata should be escaped
        assert 'admin' not in properties

    def test_break_by_crypto(self, oracle: CommentsOracle) -> None:
        pass
