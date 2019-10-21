#!/usr/bin/env python3

import base64
import pathlib

from Crypto.Cipher import AES


RESULT = b"I'm back and I'm ringin' the bell "


def challenge07(path: str) -> bytes:
    key = b"YELLOW SUBMARINE"
    cipher = AES.new(key, AES.MODE_ECB)

    with open(path) as f:
        lines = f.readlines()

    cipher_text = base64.b64decode("".join(lines))

    msg = cipher.decrypt(cipher_text).split(b"\n")

    return msg[0]


if __name__ == "__main__":
    res = challenge07(
        pathlib.Path(__file__).absolute().parent.parent.parent / "data" / "7.txt"
    )

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
