#!/usr/bin/env python3

from functions.aes import pkcs7_pad


TEXT = b"YELLOW SUBMARINE"
RESULT = b"YELLOW SUBMARINE\x04\x04\x04\x04"


def challenge09(bytes_: bytes, block_size: int) -> bytes:
    return pkcs7_pad(bytes_, block_size)


if __name__ == "__main__":
    res = challenge09(TEXT, 20)

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
