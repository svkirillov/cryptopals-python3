#!/usr/bin/env python3

from functions import aes


TEXT = b"YELLOW SUBMARINE"
RESULT = b"YELLOW SUBMARINE\x04\x04\x04\x04"


def challenge09(bytes_: bytes, block_size: int) -> bytes:
    return aes.pkcs7_padding_add(bytes_, block_size)


if __name__ == "__main__":
    res = challenge09(TEXT, 20)

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
