import pytest
from random import randint
from cryptopals.adversary import brute_force_ecb_unknown_string
from cryptopals.oracle import EcbUnknownStringOracle


class TestChallenge14():

    # Test 4 iterations since it is a random function
    @pytest.mark.parametrize('_', range(4))
    def test_break_unknown_string_oracle(self, _: int) -> None:
        # Initialize oracles with random prefix sizes
        # NOTE: currently only works if {prefix_size} < {block_size}
        oracle: EcbUnknownStringOracle = EcbUnknownStringOracle(prefix_size=randint(0, 15))

        # Use adversary to retrieve the unknown string within the oracle
        assert brute_force_ecb_unknown_string(oracle) == oracle.unknown_string
