from typing import cast, TYPE_CHECKING
from Crypto.Cipher import AES
from Crypto.Cipher._mode_ecb import EcbMode
from Crypto.Cipher._mode_cbc import CbcMode
from .parent import Text

# Only import early if type checking is active
if TYPE_CHECKING:  # pragma: no cover
    from . import Ciphertext


# Type hint for plaintext
# Provides methods for encrypting and padding
#
# NOTE: Both ciphertext and plaintext are both just a string of bytes.
#       However, here are two separate classes to provide better type hints throughout the code base.
class Plaintext(Text):

    # Save space
    __slots__: tuple[()] = ()

    def encrypt_ecb_mode(self, key: Text) -> 'Ciphertext':
        # Import Ciphertext class later to avoid circular dependencies
        from . import Ciphertext

        # Create AES cipher stream and cast to correct type
        stream: EcbMode = cast(EcbMode, AES.new(key.to_bytes(), AES.MODE_ECB))

        # Encrypt
        return Ciphertext(
            stream.encrypt(self.pkcs7_pad().to_bytes()),
            block_size=self.block_size
        )

    def encrypt_cbc_mode(self, key: Text, iv: Text) -> 'Ciphertext':
        # Import Ciphertext class later to avoid circular dependencies
        from . import Ciphertext

        # Create AES cipher stream and cast to correct type
        stream: CbcMode = cast(CbcMode, AES.new(key.to_bytes(), AES.MODE_CBC, iv=iv.to_bytes()))

        # Encrypt
        return Ciphertext(
            stream.encrypt(self.pkcs7_pad().to_bytes()),
            block_size=self.block_size
        )

    # Pad Text based on block size
    def pkcs7_pad(self) -> 'Plaintext':
        # Calculate the desired length based on the $block_size
        # After the padding the string should be longer, so we calculate how many times the $block_size fits in the
        # input and then add 1 extra block
        desired_length: int = (self.length // self.block_size + 1) * self.block_size
        difference: int = desired_length - self.length

        return Plaintext.from_iterable(
            (
                self.get_byte(index) if index < self.length else difference
                for index in range(desired_length)
            ),
            block_size=self.block_size
        )

    def pkcs7_unpad(self) -> 'Plaintext':
        # The value of last byte indicates how many bytes were padded
        difference: int = self.get_byte(-1)

        # Verify that all padded bytes have the same value
        if not all(byte == difference for byte in self.get_byte_range(-difference, self.length)):
            raise Exception('Invalid padding')

        # Remove that number of bytes from the end
        return Plaintext(
            self.get_byte_range(0, self.length - difference),
            block_size=self.block_size
        )
