from base64 import b64encode, b64decode

# Use ASCII encoding to avoid any encodings with multi-byte or variable length characters
CHARACTOR_ENCODING = 'ascii'


def bytes_to_string(value: bytes) -> str:
    return value.decode(CHARACTOR_ENCODING)


def string_to_bytes(value: str) -> bytes:
    return value.encode(CHARACTOR_ENCODING)


def hexadecimal_to_bytes(value: str) -> bytes:
    return bytes.fromhex(value)


def bytes_to_hexadecimal(value: bytes) -> str:
    return value.hex()


def bytes_to_base64(value: bytes) -> str:
    return bytes_to_string(b64encode(value))


def base64_to_bytes(value: str) -> bytes:
    return b64decode(string_to_bytes(value))
