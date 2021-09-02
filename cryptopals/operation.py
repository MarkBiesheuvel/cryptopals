
# Function that takes two equal-length bytes and produces their XOR combination
def fixed_xor(input_a: bytes, input_b: bytes) -> bytes:
    if len(input_a) != len(input_b):
        raise Exception('Invalid operation')

    # Python does not support bitwise operations on bytes, so we need to XOR byte-by-byte
    return bytes(a ^ b for a, b in zip(input_a, input_b))


def single_byte_xor(cipher: bytes, key: int) -> bytes:
    if key < 0 or 255 < key:
        raise Exception('Invalid operation')

    return bytes(byte ^ key for byte in cipher)


def repeating_key_xor(cipher: bytes, key: bytes) -> bytes:
    key_length = len(key)
    return bytes(byte ^ key[i % key_length] for (i, byte) in enumerate(cipher))


def pkcs7_pad(input: bytes, block_size: int) -> bytes:
    input_length = len(input)
    # Calculate the desired length based on the $block_size
    # After the padding the string should be longer, so we calculate how many times the $block_size fits in the input
    # and then add 1 extra block
    desired_length = (input_length // block_size + 1) * block_size
    difference = desired_length - input_length

    return bytes([
        input[i] if i < input_length else difference
        for i in range(desired_length)
    ])


def pkcs7_unpad(input: bytes) -> bytes:
    difference = input[-1]
    return input[:-difference]
