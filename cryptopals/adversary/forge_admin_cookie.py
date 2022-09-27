from .detect_block_size import detect_block_size
from ..oracle import Oracle
from .. import Block, Ciphertext, Plaintext

# Assumption: we know that all profile will be prefixed with "email="
PROFILE_PREFIX: str = 'email='

# A random but valid domain name for our email address
DOMAIN_NAME: str = '@example.com'

# The role that is assigned by default, used in length calculation
DEFAULT_ROLE: str = 'user'

# The role we want to forge
DESIRED_ROLE: str = 'admin'


# We can only supply the email field in the profile, but want to set the role field to admin
#
# Assumption: the role field is last in the list, so if we carefully construct our email address the word admin will
# fall into its own block. The block will be padded to the {block_size}
# The last two blocks we desire would look something like this (where X, Y, and Z are some variable)
# X&uid=YYYY&role=
# adminZZZZZZZZZZZ
#
# We can construct an email address that includes this sequence of bytes and align it so that it aligns with a block
# That would look something like this (where A, B and Z are some variable):
# email=AAAAAAAAAA
# adminZZZZZZZZZZZ
# @gmail.com&uid=B
#
# After encrypting our carefully chosen email address we can copy past it to the end of a cipher
def forge_admin_cookie(oracle: Oracle) -> Ciphertext:
    # Detect the block size
    block_size: int
    additional_string_length: int
    block_size, additional_string_length = detect_block_size(oracle)

    # Build the desired last block
    desired_last_block: Block = get_desired_last_block(oracle, block_size)

    # Build a normal cipher (which aligns so the last block can be replaced)
    ciphertext: Ciphertext = forge_ciphertext(oracle, block_size, additional_string_length)

    # Forge a cipher by using the all blocks from the cipher except the last and only the desired last block
    return Ciphertext(
        ciphertext.get_byte_range(0, ciphertext.length - block_size) + desired_last_block.to_bytes(),
        block_size=block_size
    )


def get_desired_last_block(oracle: Oracle, block_size: int) -> Block:
    # Generate our desired last block using pkcs#7 padding
    plaintext: Plaintext = Plaintext.from_ascii(
        DESIRED_ROLE,
        block_size=block_size
    ).pkcs7_pad()

    # Determine how many characters we need to prepend by comparing the {block_size} to the length of "email="
    prefix: Plaintext = Plaintext.fixed_bytes(
        length=block_size - len(PROFILE_PREFIX),
        block_size=block_size
    )

    # Construct the plaintext, trying to make it look like an email address
    domain: Plaintext = Plaintext.from_ascii(
        DOMAIN_NAME,
        block_size=block_size
    )
    email: Plaintext = (prefix + plaintext + domain)

    # Encrypt our profile using the oracle
    ciphertext: Ciphertext = oracle.encrypt(email)

    # Retrieve the 2nd block to be used as last block later
    return ciphertext.get_block(1)


def forge_ciphertext(oracle: Oracle, block_size: int, additional_string_length: int) -> Ciphertext:
    # Calculate how long our email address needs to be in order for it to fit perfectly in a multiple of $block_size
    # excluding the length of the default role and including the domain name we use
    prefix_length: int = (block_size - (additional_string_length - len(DEFAULT_ROLE) + len(DOMAIN_NAME))) % block_size

    # Construct "valid" email address of desired length
    prefix: Plaintext = Plaintext.fixed_bytes(
        length=prefix_length,
        block_size=block_size
    )
    domain: Plaintext = Plaintext.from_ascii(
        DOMAIN_NAME,
        block_size=block_size
    )
    email: Plaintext = (prefix + domain)

    return oracle.encrypt(email)
