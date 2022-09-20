from __future__ import annotations
from Crypto.Cipher import AES
from .parent import Text

# NOTE: cannot load Plaintext using "from . import" as it would cause a circular dependency
import cryptopals


# Type hint for ciphertext
# Provides methods for decrypting
#
# NOTE: Both ciphertext and plaintext are both just a string of bytes.
#       However, here are two separate classes to provide better type hints throughout the code base.
class Ciphertext(Text):

    def decrypt_ecb_mode(self, key: Text) -> cryptopals.Plaintext:
        # TODO: add type hint to {stream}
        stream = AES.new(key.to_bytes(), AES.MODE_ECB)

        plaintext: cryptopals.Plaintext = cryptopals.Plaintext(
            stream.decrypt(self.to_bytes()),
            block_size=self.block_size
        )

        return plaintext.pkcs7_unpad()

    def decrypt_cbc_mode(self, key: Text, iv: Text) -> cryptopals.Plaintext:
        # TODO: add type hint to {stream}
        stream = AES.new(key.to_bytes(), AES.MODE_CBC, iv=iv.to_bytes())

        plaintext: cryptopals.Plaintext = cryptopals.Plaintext(
            stream.decrypt(self.to_bytes()),
            block_size=self.block_size
        )

        return plaintext.pkcs7_unpad()
