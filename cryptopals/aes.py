# TODO: implement by hand
# I realize using a library is considered "cheating" however I want to prioritize learning from the other challenges
from Crypto.Cipher import AES
from enum import Enum
from .operation import pkcs7_pad, pkcs7_unpad

BLOCK_SIZE = AES.block_size  # 16


class BlockCipherMode(Enum):
    ECB = AES.MODE_ECB  # 1
    CBC = AES.MODE_CBC  # 2


def encrypt_ebc_mode(plaintext: bytes, key: bytes) -> bytes:
    stream = AES.new(key, AES.MODE_ECB)
    return stream.encrypt(pkcs7_pad(plaintext, BLOCK_SIZE))


def decrypt_ecb_mode(cipher: bytes, key: bytes) -> bytes:
    stream = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(stream.decrypt(cipher))


def encrypt_cbc_mode(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    stream = AES.new(key, AES.MODE_CBC, iv=iv)
    return stream.encrypt(pkcs7_pad(plaintext, BLOCK_SIZE))


def decrypt_cbc_mode(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    stream = AES.new(key, AES.MODE_CBC, iv=iv)
    return pkcs7_unpad(stream.decrypt(cipher))
