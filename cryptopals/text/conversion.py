from base64 import b64encode, b64decode

# Use ASCII encoding to avoid any encodings with multi-byte or variable length characters
CHARACTOR_ENCODING = 'ascii'


def bytes_to_string(input: bytes):
    return input.decode(CHARACTOR_ENCODING)


def string_to_bytes(input: str):
    return input.encode(CHARACTOR_ENCODING)


# Function that convert a string with hexidecimal digits to bytes
# Challanges often give the input in this format, so this is used to convert that input
def hexadecimal_to_bytes(input: str) -> bytes:
    return bytes.fromhex(input)


def bytes_to_hexadecimal(input: bytes) -> str:
    return input.hex()


# Function that convert bytes to a base64 encoded string
def bytes_to_base64(input: bytes) -> str:
    return bytes_to_string(b64encode(input))


def base64_to_bytes(input: str) -> bytes:
    return b64decode(string_to_bytes(input))
