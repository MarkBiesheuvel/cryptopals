from base64 import b64encode, b64decode

# Use ISO/IEC 8859 encoding to ...
# 1. avoid any encodings with multi-byte or variable length characters
# 2. use the full 8 bits of a byte (compared to ASCII which only uses 7 bits)
CHARACTER_ENCODING = 'iso-8859-1'


def bytes_to_string(value: bytes) -> str:
    return value.decode(CHARACTER_ENCODING)


def string_to_bytes(value: str) -> bytes:
    return value.encode(CHARACTER_ENCODING)


def hexadecimal_to_bytes(value: str) -> bytes:
    return bytes.fromhex(value)


def bytes_to_hexadecimal(value: bytes) -> str:
    return value.hex()


def bytes_to_base64(value: bytes) -> str:
    return bytes_to_string(b64encode(value))


def base64_to_bytes(value: str) -> bytes:
    return b64decode(string_to_bytes(value))
