from typing import Iterable


def file_iterator(filename: str) -> Iterable[str]:
    with open(filename, 'r') as file:
        while True:
            line: str = file.readline()
            if line == '':
                break
            else:
                yield line.strip()
