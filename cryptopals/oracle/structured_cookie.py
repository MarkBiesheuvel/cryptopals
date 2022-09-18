from typing import Iterable, List, Dict
from .oracle import Oracle
from ..text import Text

CHARACTER_AMPERSAND = '&'
CHARACTER_EQUALS_SIGN = '='


class StructuredCookieOracle(Oracle):

    def __init__(self):
        super(StructuredCookieOracle, self).__init__()

        # Autoincrement ID, but use a starting position where it's unlikely to impact padding
        self.lastest_id = 1337

    def parse(self, profile: Text) -> Dict[str, str]:
        pairs: Iterable[List[str]] = (
            pair.split(CHARACTER_EQUALS_SIGN)
            for pair in profile.to_ascii().split(CHARACTER_AMPERSAND)
        )

        return {
            pair[0]: pair[1]
            for pair in pairs
        }

    def profile_for(self, email: Text) -> Text:
        if not email.is_printable():
            raise Exception('Unreadable email')  # pragma: no cover

        # TODO: Detect based on byte value
        if CHARACTER_AMPERSAND in email.to_ascii() or CHARACTER_EQUALS_SIGN in email.to_ascii():
            raise Exception('Forbidded character in email')  # pragma: no cover

        # Simulate a website where user ids automatically increment
        self.lastest_id += 1

        # TODO: verify whether this is the best way to perform byte interpolation
        value: bytes = b'email=%b&uid=%a&role=user' % (email.to_bytes(), self.lastest_id)
        return Text(value)

    def encrypt(self, email: Text) -> Text:
        profile: Text = self.profile_for(email)
        return profile.encrypt_ebc_mode(self.key)

    def decrypt(self, ciphertext: Text) -> Dict[str, str]:
        profile: Text = ciphertext.decrypt_ecb_mode(self.key)
        return self.parse(profile)
