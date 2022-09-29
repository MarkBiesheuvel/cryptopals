from cryptopals import Ciphertext
from cryptopals.adversary import forge_admin_cookie
from cryptopals.oracle import StructuredCookieOracle


class TestChallenge13:

    def test_break_structured_cookie_oracle(self) -> None:
        oracle: StructuredCookieOracle = StructuredCookieOracle()
        ciphertext: Ciphertext = forge_admin_cookie(oracle)

        forged_profile: dict[str, str] = oracle.decrypt(ciphertext)
        assert forged_profile['role'] == 'admin'
