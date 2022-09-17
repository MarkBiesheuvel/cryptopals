from Crypto.Cipher import AES
from enum import Enum


class BlockCipherMode(Enum):
    ECB = AES.MODE_ECB  # 1
    CBC = AES.MODE_CBC  # 2
