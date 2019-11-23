#!/usr/bin/env python3

import base64
import pathlib

from functions.xor import guess_key_length, bruteforce_xor_multi_byte_key


RESULT = b"Terminator X: Bring the noise"


def challenge06(path: str) -> bytes:
    with open(path) as file:
        cipher = base64.b64decode(file.read())

    keysize = guess_key_length(cipher)
    key = bruteforce_xor_multi_byte_key(cipher, keysize)

    return key


if __name__ == "__main__":
    res = challenge06(
        pathlib.Path(__file__).absolute().parent.parent.parent / "data" / "6.txt"
    )

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
