from collections.abc import Iterable
from .oracle import Oracle
from .. import Ciphertext, Plaintext

CHARACTER_AMPERSAND: str = '&'
CHARACTER_EQUALS_SIGN: str = '='


class StructuredCookieOracle(Oracle):

    # Autoincrement ID, but use a starting position where it's unlikely to impact padding
    latest_id: int = 1337

    def profile_for(self, email: Plaintext) -> Plaintext:
        if not email.is_printable():
            raise ValueError('Unreadable email')

        # Convert to ASCII string for this part, as it's easier
        email_string: str = email.to_ascii()

        # Check for forbidden characters
        if CHARACTER_AMPERSAND in email_string or CHARACTER_EQUALS_SIGN in email_string:
            raise ValueError('Forbidden character in email')

        # Simulate a website where user ids automatically increment
        self.latest_id += 1

        # Build structured cookie profile
        profile: str = f'email={email_string}&uid={self.latest_id}&role=user'

        return Plaintext.from_ascii(profile)

    def encrypt(self, email: Plaintext) -> Ciphertext:
        profile: Plaintext = self.profile_for(email)
        return profile.encrypt_ecb_mode(self.key)

    def decrypt(self, ciphertext: Ciphertext) -> dict[str, str]:
        profile: Plaintext = ciphertext.decrypt_ecb_mode(self.key)

        pairs: Iterable[list[str]] = (
            pair.split(CHARACTER_EQUALS_SIGN)
            for pair in profile.to_ascii().split(CHARACTER_AMPERSAND)
        )

        return {
            pair[0]: pair[1]
            for pair in pairs
        }
