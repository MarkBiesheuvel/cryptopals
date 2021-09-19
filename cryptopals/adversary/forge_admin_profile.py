from .detect_block_size import detect_block_size
from ..oracle import Oracle
from ..aes import BLOCK_SIZE
from ..operation import pkcs7_pad, get_block, nonrandom_bytes

# Assumtion: we know that all profile will be prefixed with "email="
PROFILE_PREFIX = b'email='

# A random but valid domain name for our email address
DOMAIN_NAME = b'@example.com'

# The role that is assigned by default, used in length calculation
DEFAULT_ROLE = b'user'

# The role we want to forge
DESIRED_ROLE = b'admin'


# We can only supply the email field in the profile, but want to set the role field to admin
#
# Assumption: the role field is last in the list, so if we carefully construct our email adress the word admin will
# fall into its own block. The block will be padded to the BLOCK_SIZE
# The last two blocks we desire would look something like this (where X, Y, and Z are some variable)
# X&uid=YYYY&role=
# adminZZZZZZZZZZZ
#
# We can construct an email address that includes this sequence of bytes and allign it so that it alligns with a block
# That would look something like this (where A, B and Z are some variable):
# email=AAAAAAAAAA
# adminZZZZZZZZZZZ
# @gmail.com&uid=B
#
# After encrypting our carefully chosen email addres we can copy past it to the end of a cipher
def forge_admin_profile(oracle: Oracle) -> bytes:
    # Detect the block size
    block_size, additional_string_length = detect_block_size(oracle)

    # Build the desired last block
    desired_last_block = get_desired_last_block(oracle, block_size,)

    # Build a normal cipher (which aligns so the last block can be replaced)
    cipher: bytes = get_cipher(oracle, block_size, additional_string_length)

    # Forge a cipher by using the all blocks from the cipher except the last and only the desired last block
    return cipher[0:len(cipher)-block_size] + desired_last_block


def get_desired_last_block(oracle: Oracle, block_size: int) -> bytes:
    # Generate our desired last block using pkcs#7 padding
    plaintext: bytes = pkcs7_pad(DESIRED_ROLE, block_size)

    # Determine how many characters we need to prepend by comparing the BLOCK_SIZE to the length of "email="
    prefix: bytes = nonrandom_bytes(block_size - len(PROFILE_PREFIX))

    # Construct the plaintext, trying to make it look like an email address
    email: bytes = prefix + plaintext + DOMAIN_NAME

    # Encrypt our profile using the oracle
    cipher: bytes = oracle.encrypt(email)

    # Retrieve the 2nd block to be used as last block later
    return get_block(cipher, 1, block_size)


def get_cipher(oracle: Oracle, block_size: int, additional_string_length: int) -> bytes:
    # Calculate how long our email address needs to be in order for it to fit perfectly in a multiple of $block_size
    # excluding the length of the default role and including the domain name we use
    email_length = block_size - (additional_string_length - len(DEFAULT_ROLE) + len(DOMAIN_NAME)) % block_size

    # Construct email address of desired length
    email = nonrandom_bytes(email_length) + DOMAIN_NAME

    return oracle.encrypt(email)
