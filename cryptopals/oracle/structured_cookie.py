from typing import Iterable, List, Dict
from .oracle import Oracle
from .. import Ciphertext, Plaintext

CHARACTER_AMPERSAND: str = '&'
CHARACTER_EQUALS_SIGN: str = '='


class StructuredCookieOracle(Oracle):

    # Autoincrement ID, but use a starting position where it's unlikely to impact padding
    lastest_id: int = 1337

    def profile_for(self, email: Plaintext) -> Plaintext:
        if not email.is_printable():
            raise Exception('Unreadable email')  # pragma: no cover

        # Convert to ASCII string for this part, as it's easier
        email_string: str = email.to_ascii()

        # Check for forbidden characters
        if CHARACTER_AMPERSAND in email_string or CHARACTER_EQUALS_SIGN in email_string:
            raise Exception('Forbidded character in email')  # pragma: no cover

        # Simulate a website where user ids automatically increment
        self.lastest_id += 1

        # Build structured cookie profile
        profile: str = 'email={email}&uid={id}&role=user'.format(
            email=email_string,
            id=self.lastest_id
        )

        return Plaintext.from_ascii(profile)

    def encrypt(self, email: Plaintext) -> Ciphertext:
        profile: Plaintext = self.profile_for(email)
        return profile.encrypt_ebc_mode(self.key)

    def decrypt(self, ciphertext: Ciphertext) -> Dict[str, str]:
        profile: Plaintext = ciphertext.decrypt_ecb_mode(self.key)

        pairs: Iterable[List[str]] = (
            pair.split(CHARACTER_EQUALS_SIGN)
            for pair in profile.to_ascii().split(CHARACTER_AMPERSAND)
        )

        return {
            pair[0]: pair[1]
            for pair in pairs
        }
