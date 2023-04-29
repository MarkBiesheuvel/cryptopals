from collections.abc import Iterable
from cryptopals import Ciphertext
from cryptopals.adversary import find_aes_ecb_cipher
from ..helpers import file_iterator


class TestChallenge08:

    def test_detect_aes_in_ecb_mode(self) -> None:
        ciphertexts: Iterable[Ciphertext] = (
            Ciphertext.from_hexadecimal(line)
            for line in file_iterator('../data/8.txt')
        )
        ecb_ciphertext: Ciphertext = Ciphertext.from_hexadecimal(
            'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf'
            '9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a'
            '08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4f'
            'd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'
        )

        assert find_aes_ecb_cipher(ciphertexts) == ecb_ciphertext
