from typing import Iterable, List, Dict
from .oracle import Oracle
from .. import Block, Ciphertext, Plaintext

CHARACTER_SEPERATOR: str = ';'
CHARACTER_EQUALS: str = '='

ESCAPED_CHARACTERS: Dict[str, str] = {
    CHARACTER_SEPERATOR: '%3B',
    CHARACTER_EQUALS: '%3D',
}


class CommentsOracle(Oracle):

    def __init__(self) -> None:
        super(CommentsOracle, self).__init__()

        # IV needed for CBC mode
        self.iv: Block = Block.random_bytes(length=self.key.length)

    @staticmethod
    def comments_for(userdata: Plaintext) -> Plaintext:
        # Convert to string to make operations easier
        data: str = userdata.to_ascii()

        # Escape any special characters
        for character, replacement in ESCAPED_CHARACTERS.items():
            # Only run replace function if character was found
            if character in data:
                data = data.replace(character, replacement)

        # Build a dictionary with all values
        properties: Dict[str, str] = {
            'comment1': 'cooking%20MCs',
            'userdata': data,
            'comment2': '%20like%20a%20pound%20of%20bacon'
        }

        # Join everything into a string and convert to Plaintext object
        return Plaintext.from_ascii(
            ';'.join(f'{key}={value}' for key, value in properties.items())
        )

    def encrypt(self, userdata: Plaintext) -> Ciphertext:
        plaintext: Plaintext = self.comments_for(userdata)

        return plaintext.encrypt_cbc_mode(self.key, self.iv)

    def decrypt(self, ciphertext: Ciphertext) -> Dict[str, str]:
        properties: Plaintext = ciphertext.decrypt_cbc_mode(self.key, self.iv)

        # NOTE: Disable the is_printable verification to allow a bitflip attack to work
        datastring: str = properties.to_ascii(safe_mode=False)

        pairs: Iterable[List[str]] = (
            pair.split(CHARACTER_EQUALS)
            for pair in datastring.split(CHARACTER_SEPERATOR)
        )

        return {
            pair[0]: pair[1]
            for pair in pairs
        }
