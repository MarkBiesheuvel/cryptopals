from typing import Dict
from cryptopals import Ciphertext
from cryptopals.adversary import forge_admin_profile
from cryptopals.oracle import StructuredCookieOracle


class TestChallenge13:

    def test_break_structured_cookie_oracle(self) -> None:
        oracle: StructuredCookieOracle = StructuredCookieOracle()
        ciphertext: Ciphertext = forge_admin_profile(oracle)

        forged_profile: Dict[str, str] = oracle.decrypt(ciphertext)
        assert forged_profile['role'] == 'admin'
