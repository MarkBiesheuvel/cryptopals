from __future__ import annotations
from typing import Iterable, List
from Crypto.Cipher import AES
from math import ceil
from random import randrange
from .conversion import (
    string_to_bytes,
    base64_to_bytes,
    hexadecimal_to_bytes,
    bytes_to_string,
    bytes_to_hexadecimal
)

# The byte value of an arbitrary character to be used in building nonrandom/fixed plaintext.
# Using a NULL byte (0x00) might be raise suspicion in an oracle, so let's use an alphanumeric character instead.
# The value 85 (0x55 or 'U') is chosen because the binary pattern looks fun: 0101 0101
DEFAULT_CHARACTER: int = 85

# If no block size is specified, use the AES block size (16)
DEFAULT_BLOCK_SIZE: int = AES.block_size

# List of printable ASCII characters (9-12 and 32-125)
PRINTABLE_CHARACTERS: List[int] = [
    9, 10, 11, 12, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56,
    57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
    86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125
]


# Class to represent either a plaintext or ciphertext
class Text:

    # ============ #
    # CONSTRUCTORS #
    # ============ #

    # Initializer
    def __init__(self, value: bytes, /, *, block_size: int = DEFAULT_BLOCK_SIZE):
        self.value = value
        self.length = len(value)
        self.block_size = block_size

    # Initialize a new Text from a ASCII encoded string
    @staticmethod
    def from_ascii(value: str, /, *, block_size: int = DEFAULT_BLOCK_SIZE) -> Text:
        return Text(string_to_bytes(value), block_size=block_size)

    # Initialize a new Text from a base64 encoded sring
    @staticmethod
    def from_base64(value: str, /, *, block_size: int = DEFAULT_BLOCK_SIZE) -> Text:
        return Text(base64_to_bytes(value), block_size=block_size)

    # Initialize a new Text from a hexadecimal string
    @staticmethod
    def from_hexadecimal(value: str, /, *, block_size: int = DEFAULT_BLOCK_SIZE) -> Text:
        return Text(hexadecimal_to_bytes(value), block_size=block_size)

    # Initialize a new Text from an Iterable of ints
    @staticmethod
    def from_iterable(value: Iterable[int], /, *, block_size: int = DEFAULT_BLOCK_SIZE) -> Text:
        return Text(bytes(value), block_size=block_size)

    # Initialize a new Text of {length} containing random bytes
    @staticmethod
    def random_bytes(*, length: int, block_size: int = DEFAULT_BLOCK_SIZE) -> Text:
        return Text.from_iterable((randrange(256) for _ in range(length)), block_size=block_size)

    # Initialize a new Text of {length} containing fixed bytes
    @staticmethod
    def fixed_bytes(*, length: int, block_size: int = DEFAULT_BLOCK_SIZE, fixed_byte=DEFAULT_CHARACTER) -> Text:
        return Text.from_iterable((fixed_byte for _ in range(length)), block_size=block_size)

    # ================ #
    # BLOCK OPERATIONS #
    # ================ #

    # Return a single byte (block of size 1)
    def get_byte(self, index: int) -> int:
        return self.value[index]

    # Get a range of bytes
    def get_byte_range(self, start_index: int, end_index: int) -> bytes:
        return self.value[start_index:end_index]

    # Return the block at the {block_index}
    def get_block(self, block_index: int) -> bytes:
        start_index: int = self.block_size * block_index
        end_index: int = self.block_size * (block_index + 1)
        return self.get_byte_range(start_index, end_index)

    # Return all blocks of this Text
    def get_blocks(self) -> Iterable[bytes]:
        number_of_blocks: int = ceil(self.length / self.block_size)
        return (
            self.get_block(block_index)
            for block_index in range(number_of_blocks)
        )

    # =============== #
    # X-OR OPERATIONS #
    # =============== #

    # Xor operation between two Texts
    def fixed_xor(self, other: Text) -> Text:
        if self.length != other.length:
            raise Exception('Invalid operation')

        # Python does not support bitwise operations on bytes, so we need to XOR byte-by-byte
        return Text.from_iterable(a ^ b for a, b in zip(self.to_bytes(), other.to_bytes()))

    # Xor operation between Text and a sinlge byte key (given as int)
    def single_byte_xor(self, key: int) -> Text:
        if key < 0 or 255 < key:
            raise Exception('Invalid operation')

        # Xor each byte of the Text with the same key
        return Text.from_iterable(byte ^ key for byte in self.to_bytes())

    # Xor operation between Text and a multi byte key
    def repeating_key_xor(self, key: bytes) -> Text:
        # TODO: convert key from bytes to Text
        key_length: int = len(key)

        return Text.from_iterable(byte ^ key[i % key_length] for (i, byte) in enumerate(self.to_bytes()))

    # ===================== #
    # MATH/LOGIC OPERATIONS #
    # ===================== #

    # Returns Hamming distance between two Texts
    def hamming_distance(self, other: Text) -> int:
        # By computing the XOR, all bits that were different are 1, all bits that were the same are zero
        difference: Text = self.fixed_xor(other)

        # Count the number of 1s in the difference
        return sum(
            (byte >> i) & 1  # Count the bit if it is 1 (and thus was different)
            for byte in difference.to_bytes()
            for i in range(8)  # Eight bits in a byte
        )

    # Return whether this Text contains only printable ASCII chracters
    def is_printable(self) -> bool:
        return all(byte in PRINTABLE_CHARACTERS for byte in self.to_bytes())

    # ===================== #
    # CONVERSION OPERATIONS #
    # ===================== #

    # Return bytes value
    def to_bytes(self) -> bytes:
        return self.value

    # Encode as ASCII string
    # Assumption: value does not contain unprintable characters
    def to_ascii(self) -> str:
        if not self.is_printable():
            raise Exception('Text contains unprintable characters')

        return bytes_to_string(self.value)

    # ======================== #
    # CRYPTOGRAPHIC OPERATIONS #
    # ======================== #
    # TODO: find type of stream, and move to test (so it doesn't create a new stream for each operation)

    def encrypt_ebc_mode(self, key: Text) -> Text:
        stream = AES.new(key.to_bytes(), AES.MODE_ECB)
        return Text(
            stream.encrypt(self.pkcs7_pad().to_bytes()),
            block_size=self.block_size
        )

    def decrypt_ecb_mode(self, key: Text) -> Text:
        stream = AES.new(key.to_bytes(), AES.MODE_ECB)
        return Text(
            stream.decrypt(self.to_bytes()),
            block_size=self.block_size
        ).pkcs7_unpad()

    def encrypt_cbc_mode(self, key: Text, iv: Text) -> Text:
        stream = AES.new(key.to_bytes(), AES.MODE_CBC, iv=iv.to_bytes())
        return Text(
            stream.encrypt(self.pkcs7_pad().to_bytes()),
            block_size=self.block_size
        )

    def decrypt_cbc_mode(self, key: Text, iv: Text) -> Text:
        stream = AES.new(key.to_bytes(), AES.MODE_CBC, iv=iv.to_bytes())
        return Text(
            stream.decrypt(self.to_bytes()),
            block_size=self.block_size
        ).pkcs7_unpad()

    # Pad Text based on block size
    def pkcs7_pad(self) -> Text:
        # Calculate the desired length based on the $block_size
        # After the padding the string should be longer, so we calculate how many times the $block_size fits in the
        # input and then add 1 extra block
        desired_length: int = (self.length // self.block_size + 1) * self.block_size
        difference: int = desired_length - self.length

        return Text.from_iterable(
            (
                self.get_byte(index) if index < self.length else difference
                for index in range(desired_length)
            ),
            block_size=self.block_size
        )

    def pkcs7_unpad(self) -> Text:
        # The value of last byte indicates how many bytes were padded
        difference: int = self.get_byte(-1)

        # Verify that all padded bytes have the same value
        if not all(byte == difference for byte in self.get_byte_range(-difference, self.length)):
            raise Exception('Invalid padding')

        # Remove that number of bytes from the end
        return Text(
            self.get_byte_range(0, self.length - difference),
            block_size=self.block_size
        )

    # ============= #
    # MAGIC METHODS #
    # ============= #

    # Return a string representation of the Text
    # Blocks of {block_size} are separated by space
    def __str__(self) -> str:
        return ' '.join(
            bytes_to_hexadecimal(block)
            for block in self.get_blocks()
        )

    def __repr__(self) -> str:
        return self.to_ascii() if self.is_printable() else self.__str__()

    # Returns whether two texts are equal
    # In this case {block_size} is ignored
    def __eq__(self, other: object) -> bool:
        if isinstance(other, self.__class__):
            return self.to_bytes() == other.to_bytes()
        else:
            return False

    # Add two Texts together if the block_size is equal
    def __add__(self, other: object) -> Text:
        if isinstance(other, self.__class__):
            if self.block_size != other.block_size:
                raise Exception('Unequal block size. Are these intended to be added?')

            return Text(
                self.to_bytes() + other.to_bytes(),
                block_size=self.block_size
            )

        elif isinstance(other, int):
            return Text(
                self.to_bytes() + bytes([other]),
                block_size=self.block_size
            )

        else:
            raise Exception('Incompatible types')
