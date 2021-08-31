from base64 import b64encode

CHARACTOR_ENCODING = 'utf-8'


def bytes_to_string(input: bytes):
    return input.decode(CHARACTOR_ENCODING)


def string_to_bytes(input: str):
    return input.encode(CHARACTOR_ENCODING)


# Function that convert a string with hexidecimal digits to bytes
# Challanges often give the input in this format, so this is used to convert that input
def hexadecimal_to_bytes(input: str) -> bytes:
    return bytes.fromhex(input)


def bytes_to_hexadecimal():
    pass  # TODO: implement


# Function that convert bytes to a base64 encoded string
def bytes_to_base64(input: bytes) -> str:
    return bytes_to_string(b64encode(input))


def base64_to_bytes():
    pass  # TODO: implement
