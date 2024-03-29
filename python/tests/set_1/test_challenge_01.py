from cryptopals import Plaintext


class TestChallenge01:

    def test_hex_to_base64(self) -> None:
        plaintext_1: Plaintext = Plaintext.from_hexadecimal(
            '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        )
        plaintext_2: Plaintext = Plaintext.from_base64(
            'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        )

        assert plaintext_1 == plaintext_2
