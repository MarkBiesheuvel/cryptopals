from cryptopals.adversary import brute_force_ecb_unknown_string
from cryptopals.oracle import EcbUnknownStringOracle


class TestChallenge12():

    def test_break_unknown_string_oracle(self) -> None:
        oracle: EcbUnknownStringOracle = EcbUnknownStringOracle()

        assert brute_force_ecb_unknown_string(oracle) == oracle.unknown_string
