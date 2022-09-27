import pytest
from cryptopals.oracle import Oracle
from cryptopals import Block, Ciphertext, Plaintext


@pytest.fixture
def hello_world() -> Plaintext:
    return Plaintext.from_ascii('Hello, World!', block_size=4)


@pytest.fixture
def yellow_plaintext() -> Plaintext:
    return Plaintext.from_ascii('YELLOW SUBMARINE')


@pytest.fixture
def yellow_block() -> Block:
    return Block.from_ascii('YELLOW SUBMARINE')


@pytest.fixture
def yellow_ciphertext() -> Ciphertext:
    return Ciphertext(b'\xd1\xaaOex\x92eB\xfb\xb6\xdd\x87l\xd2\x05\x08`\xfa6p~E\xf4\x99\xdb\xa0\xf2[\x92#\x01\xa5')


# Any test cases for Text class that are not covered by the cryptopals challenges
class TestMiscellaneousText:

    def test_repr(self, hello_world: Plaintext) -> None:
        # Evaluating the repr should return a copy that's equal to the original
        assert eval(repr(hello_world)) == hello_world

    def test_str(self, hello_world: Plaintext) -> None:
        # Str should return the bytes as hexadecimal
        assert str(hello_world) == '48656c6c6f2c20576f726c6421'

    def test_pad_str(self, hello_world: Plaintext) -> None:
        # Str should return the bytes as hexadecimal with spaces if it can be divided in equal blocks
        assert str(hello_world.pkcs7_pad()) == '48656c6c 6f2c2057 6f726c64 21030303'

    def test_base64(self, hello_world: Plaintext) -> None:
        assert hello_world.to_base64() == 'SGVsbG8sIFdvcmxkIQ=='

    def test_hexadecimal(self, hello_world: Plaintext) -> None:
        # Str should return the bytes as hexadecimal
        assert hello_world.to_hexadecimal() == '48656c6c6f2c20576f726c6421'

    def test_subclass_unequal(self, yellow_plaintext: Plaintext, yellow_block: Block) -> None:
        # These should be unequal even though the value is the same, since the classes are different
        assert yellow_plaintext != yellow_block

    def test_exception_unprintable(self, yellow_ciphertext: Ciphertext) -> None:
        # Converting ciphertext to ascii raises Exception
        with pytest.raises(ValueError):
            yellow_ciphertext.to_ascii(safe_mode=True)

    def test_exception_add_subclass(self, yellow_plaintext: Plaintext, yellow_ciphertext: Ciphertext) -> None:
        # Adding plaintext to ciphertext raises Exception
        with pytest.raises(ValueError):
            yellow_plaintext + yellow_ciphertext

    def test_exception_add_different_block_size(self, hello_world: Plaintext, yellow_plaintext: Plaintext) -> None:
        # Adding text of different block size raises Exception
        with pytest.raises(ValueError):
            hello_world + yellow_plaintext

    def test_exception_add_incompatible_type(self, hello_world: Plaintext) -> None:
        # Adding incompatible type raises Exception
        with pytest.raises(TypeError):
            hello_world + 3.1415

    def test_exception_fixed_xor_unequal_length(self, hello_world: Plaintext, yellow_plaintext: Plaintext) -> None:
        # Xor-ing unequal length text raises Exception
        with pytest.raises(ValueError):
            hello_world.fixed_xor(yellow_plaintext, target_class=Ciphertext)

    def test_exception_single_byte_xor_invalid_byte(self, hello_world: Plaintext) -> None:
        # Xor-ing with invalid byte value raises Exception
        with pytest.raises(ValueError):
            hello_world.single_byte_xor(-1, target_class=Ciphertext)

    def test_exception_unequal_blocks(self, hello_world: Plaintext) -> None:
        # Getting blocks from text that is not divisible raises Exception
        with pytest.raises(ValueError):
            hello_world.get_blocks()

    def test_exception_block_unequal_length(self) -> None:
        # Creating Block with block_size not equal to length raises Exception
        with pytest.raises(ValueError):
            Block.from_ascii('ICE', block_size=4)
