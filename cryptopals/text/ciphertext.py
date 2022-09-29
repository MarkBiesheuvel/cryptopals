from typing import cast, TYPE_CHECKING
from Crypto.Cipher import AES
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_cbc import CbcMode
from .parent import Text

# Only import early if type checking is active
if TYPE_CHECKING:  # pragma: no cover
    from . import Plaintext


# Type hint for ciphertext
# Provides methods for decrypting
#
# NOTE: Both ciphertext and plaintext are both just a string of bytes.
#       However, here are two separate classes to provide better type hints throughout the code base.
class Ciphertext(Text):

    # Save space
    __slots__: tuple[()] = ()

    def decrypt_ecb_mode(self, key: Text) -> 'Plaintext':
        # Import Plaintext class later to avoid circular dependencies
        from . import Plaintext

        # Create AES cipher stream and cast to correct type
        stream: EcbMode = cast(EcbMode, AES.new(key.to_bytes(), AES.MODE_ECB))

        # Decrypt
        plaintext: Plaintext = Plaintext(
            stream.decrypt(self.to_bytes()),
            block_size=self.block_size
        )

        # Unpad
        return plaintext.pkcs7_unpad()

    def decrypt_cbc_mode(self, key: Text, iv: Text) -> 'Plaintext':
        # Import Plaintext class later to avoid circular dependencies
        from . import Plaintext

        # Create AES cipher stream and cast to correct type
        stream: CbcMode = cast(CbcMode, AES.new(key.to_bytes(), AES.MODE_CBC, iv=iv.to_bytes()))

        # Decrypt
        plaintext: Plaintext = Plaintext(
            stream.decrypt(self.to_bytes()),
            block_size=self.block_size
        )

        # Unpad
        return plaintext.pkcs7_unpad()
