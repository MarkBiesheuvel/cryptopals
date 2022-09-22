import pytest
from typing import List, Tuple
from cryptopals import Plaintext

TEST_CASES: List[Tuple[int, bytes]] = [
    (20, b'YELLOW SUBMARINE\x04\x04\x04\x04'),
    (31, b'YELLOW SUBMARINE\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'),
    (16, b'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'),
]


class TestChallenge09:

    @pytest.mark.parametrize('block_size, expected_value', TEST_CASES)
    def test_pkcs7_padding(self, block_size: int, expected_value: bytes) -> None:
        plaintext: Plaintext = Plaintext.from_ascii('YELLOW SUBMARINE', block_size=block_size)

        assert plaintext.pkcs7_pad() == Plaintext(expected_value)
