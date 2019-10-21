#!/usr/bin/env python3

import base64
import pathlib

from functions import aes


RESULT = b"I'm back and I'm ringin' the bell "


def challenge10(path: str) -> bytes:
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * 16

    with open(path) as f:
        lines = f.readlines()

    cipher_text = base64.b64decode("".join(lines))

    plain_text = aes.aes_cbc_decrypt(cipher_text, key, iv).split(b"\n")

    return plain_text[0]


if __name__ == "__main__":
    res = challenge10(
        pathlib.Path(__file__).absolute().parent.parent.parent / "data" / "10.txt"
    )

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
