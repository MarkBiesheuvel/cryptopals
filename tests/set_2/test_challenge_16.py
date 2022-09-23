import pytest
from typing import Dict
from cryptopals import Ciphertext, Plaintext
from cryptopals.adversary import forge_admin_comment
from cryptopals.oracle import CommentsOracle


@pytest.fixture
def oracle() -> CommentsOracle:
    return CommentsOracle()


class TestChallenge16:

    def test_cannot_break_by_userdata(self, oracle: CommentsOracle) -> None:
        # Try to be clever by entering userdata that might add the admin=true property
        plaintext: Plaintext = Plaintext.from_ascii(';admin=true')
        ciphertext: Ciphertext = oracle.encrypt(plaintext)

        # Decrypt as the oracle would normally do
        properties: Dict[str, str] = oracle.decrypt(ciphertext)

        # The admin property should not be set since the userdata should be escaped
        assert 'admin' not in properties

    def test_break_by_crypto(self, oracle: CommentsOracle) -> None:
        # Fabricate a ciphertext that will really trick the oracle
        ciphertext: Ciphertext = forge_admin_comment(oracle)

        # Decrypt as the oracle would normally do
        properties: Dict[str, str] = oracle.decrypt(ciphertext)

        # This time the admin property should be there
        assert 'admin' in properties
