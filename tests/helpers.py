from typing import Iterable
from cryptopals.conversion import hexadecimal_to_bytes


# Function that iterates over the lines in a file
def file_iterator(filename: str) -> Iterable[str]:
    with open(filename, 'r') as file:
        while True:
            line: str = file.readline()
            if line == '':
                break
            else:
                yield line.strip()


# The solution to a few challenges is the lyrics to the song "Vanilla Ice - Play That Funky Music (Ariel Shohet Remix)"
# The song can be found on YouTube: https://youtu.be/n2Ubq9XII8c
def funky_music() -> bytes:
    return hexadecimal_to_bytes(''.join(file_iterator('tests/data/n2Ubq9XII8c.txt')))
