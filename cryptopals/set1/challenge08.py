#!/usr/bin/env python3

import pathlib

from functions.aes import get_blocks


RESULT = b"\xd8\x80a\x97@\xa8\xa1\x9bx@\xa8\xa3\x1c\x81\n=\x08d\x9a\xf7\r\xc0oO\xd5\xd2\xd6\x9ctL\xd2\x83"


def challenge08(path: str) -> bytes:
    with open(path) as f:
        lines = f.readlines()

    cipher_texts = [bytes.fromhex(line) for line in lines]
    cipher_texts_blocks = [get_blocks(ct) for ct in cipher_texts]
    uniques = [len(set(ctb)) for ctb in cipher_texts_blocks]
    idx = uniques.index(min(uniques))
    ecb_encrypted = cipher_texts[idx]
    return ecb_encrypted[:32]


if __name__ == "__main__":
    res = challenge08(
        pathlib.Path(__file__).absolute().parent.parent.parent / "data" / "8.txt"
    )

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
