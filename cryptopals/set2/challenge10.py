#!/usr/bin/env python3

import base64
import pathlib

from functions.aes import AESCipher


RESULT = b"I'm back and I'm ringin' the bell "


def challenge10(path: str) -> bytes:
    key = b"YELLOW SUBMARINE"
    iv = b"\x00" * 16

    cipher = AESCipher(AESCipher.MODE_CBC, key, iv=iv)

    with open(path) as f:
        lines = f.readlines()

    cipher_text = base64.b64decode("".join(lines))

    plain_text = cipher.decrypt(cipher_text).split(b"\n")

    return plain_text[0]


if __name__ == "__main__":
    res = challenge10(
        pathlib.Path(__file__).absolute().parent.parent.parent / "data" / "10.txt"
    )

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
