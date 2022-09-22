from cryptopals import Ciphertext, Plaintext


class TestChallenge02:

    def test_fixed_xor(self) -> None:
        plaintext_1: Plaintext = Plaintext.from_hexadecimal('1c0111001f010100061a024b53535009181c')
        plaintext_2: Plaintext = Plaintext.from_hexadecimal('686974207468652062756c6c277320657965')
        ciphertext: Ciphertext = Ciphertext.from_hexadecimal('746865206b696420646f6e277420706c6179')

        assert plaintext_1.fixed_xor(plaintext_2, target_class=Ciphertext) == ciphertext
