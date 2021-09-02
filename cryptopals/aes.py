# TODO: implement by hand
# I realize using a library is considered "cheating" however I want to prioritize learning from the other challenges
from Crypto.Cipher import AES
from enum import Enum
from .operations import pkcs7_pad, pkcs7_unpad

BLOCK_SIZE = AES.block_size  # 16


class BlockCipherMode(Enum):
    ECB = AES.MODE_ECB  # 1
    CBC = AES.MODE_CBC  # 2


def aes_ecb_encrypt(plain_text: bytes, key: bytes) -> bytes:
    stream = AES.new(key, AES.MODE_ECB)
    return stream.encrypt(pkcs7_pad(plain_text, BLOCK_SIZE))


def aes_ecb_decrypt(cipher: bytes, key: bytes) -> bytes:
    stream = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(stream.decrypt(cipher))


def aes_cbc_encrypt(plain_text: bytes, key: bytes, iv: bytes) -> bytes:
    stream = AES.new(key, AES.MODE_CBC, iv=iv)
    return stream.encrypt(pkcs7_pad(plain_text, BLOCK_SIZE))


def aes_cbc_decrypt(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    stream = AES.new(key, AES.MODE_CBC, iv=iv)
    return pkcs7_unpad(stream.decrypt(cipher))
