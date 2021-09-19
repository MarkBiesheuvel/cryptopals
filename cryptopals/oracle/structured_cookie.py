from typing import Iterable, List, Dict
from .oracle import Oracle
from ..aes import encrypt_ebc_mode, decrypt_ecb_mode
from ..conversion import bytes_to_string

CHARACTER_AMPERSAND = b'&'
CHARACTER_EQUALS_SIGN = b'='


class StructuredCookieOracle(Oracle):

    def __init__(self):
        super(StructuredCookieOracle, self).__init__()

        # Autoincrement ID, but use a starting position where it's unlikely to impact padding
        self.lastest_id = 1337

    def parse(self, profile: bytes) -> Dict[bytes, bytes]:
        pairs: Iterable[List[bytes]] = (
            pair.split(CHARACTER_EQUALS_SIGN)
            for pair in profile.split(CHARACTER_AMPERSAND)
        )

        return {
            pair[0]: pair[1]
            for pair in pairs
        }

    def profile_for(self, email: bytes) -> bytes:
        if CHARACTER_AMPERSAND in email or CHARACTER_EQUALS_SIGN in email:
            raise Exception('Invalid operation')

        # Simulate a website where user ids automatically increment
        self.lastest_id += 1

        return b'email=%b&uid=%a&role=user' % (email, self.lastest_id)

    def encrypt(self, email: bytes) -> bytes:
        profile: bytes = self.profile_for(email)
        return encrypt_ebc_mode(profile, self.key)

    def decrypt(self, cipher: bytes) -> Dict[bytes, bytes]:
        profile: bytes = decrypt_ecb_mode(cipher, self.key)
        return self.parse(profile)
