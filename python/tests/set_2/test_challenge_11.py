import pytest
from cryptopals.adversary import detect_aes_block_mode
from cryptopals.oracle import RandomBlockModeOracle


class TestChallenge11:

    # Test 16 iterations since it is a random function
    @pytest.mark.parametrize('_', range(16))
    def test_detect_aes_block_mode(self, _: int) -> None:
        # Initialize a new oracle to get a new random mode and random key
        oracle: RandomBlockModeOracle = RandomBlockModeOracle()

        # Use adversary to detect the mode used by the oracle
        assert detect_aes_block_mode(oracle) == oracle.mode
