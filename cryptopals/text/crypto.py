from __future__ import annotations
from Crypto.Cipher import AES
from .parent import Text

# NOTE: Both ciphertext and plaintext are both just a string of bytes.
#       However, here are two separate classes to provide better type hints throughout the code base.


# Type hint for ciphertext
# Provides methods for decrypting
class Ciphertext(Text):

    def decrypt_ecb_mode(self, key: Text) -> Plaintext:
        # TODO: add type hint to {stream}
        stream = AES.new(key.to_bytes(), AES.MODE_ECB)

        plaintext: Plaintext = Plaintext(
            stream.decrypt(self.to_bytes()),
            block_size=self.block_size
        )

        return plaintext.pkcs7_unpad()

    def decrypt_cbc_mode(self, key: Text, iv: Text) -> Plaintext:
        # TODO: add type hint to {stream}
        stream = AES.new(key.to_bytes(), AES.MODE_CBC, iv=iv.to_bytes())

        plaintext: Plaintext = Plaintext(
            stream.decrypt(self.to_bytes()),
            block_size=self.block_size
        )

        return plaintext.pkcs7_unpad()


# Type hint for plaintext
# Provides methods for encrypting and padding
class Plaintext(Text):

    def encrypt_ebc_mode(self, key: Text) -> Ciphertext:
        stream = AES.new(key.to_bytes(), AES.MODE_ECB)
        return Ciphertext(
            stream.encrypt(self.pkcs7_pad().to_bytes()),
            block_size=self.block_size
        )

    def encrypt_cbc_mode(self, key: Text, iv: Text) -> Ciphertext:
        stream = AES.new(key.to_bytes(), AES.MODE_CBC, iv=iv.to_bytes())
        return Ciphertext(
            stream.encrypt(self.pkcs7_pad().to_bytes()),
            block_size=self.block_size
        )

    # Pad Text based on block size
    def pkcs7_pad(self) -> Plaintext:
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

    def pkcs7_unpad(self) -> Plaintext:
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
