from typing import Iterable
from cryptopals.text import Plaintext


# Function that iterates over the lines in a file
def file_iterator(filename: str) -> Iterable[str]:
    with open(filename, 'r') as file:
        while True:
            line: str = file.readline()
            if line == '':
                break
            else:
                yield line.strip()


# Function that joins all lines of a file together as a single string
def file_as_string(filename: str) -> str:
    return ''.join(file_iterator(filename))


# The solution to a few challenges is the lyrics to the song "Vanilla Ice - Play That Funky Music (Ariel Shohet Remix)"
# The song can be found on YouTube: https://youtu.be/n2Ubq9XII8c
def funky_music() -> Plaintext:
    return Plaintext.from_hexadecimal(file_as_string('tests/data/n2Ubq9XII8c.txt'))
