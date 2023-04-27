from cryptopals import Ciphertext, Plaintext


class TestChallenge05:

    def test_repeating_key_xor(self) -> None:
        # TODO: use block class and set block size of plaintext and cipher text to same size
        key: bytes = b'ICE'
        plaintext: Plaintext = Plaintext.from_ascii(
            'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
        )
        ciphertext: Ciphertext = Ciphertext.from_hexadecimal(
            '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
            'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
        )

        assert plaintext.repeating_key_xor(key, target_class=Ciphertext) == ciphertext
