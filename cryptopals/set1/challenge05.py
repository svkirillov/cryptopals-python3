#!/usr/bin/env python3

from functions.xor import xor_byte_arrays


TEXT = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

KEY = b"ICE"

RESULT = bytes.fromhex(
    "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a"
    "282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
)


def challenge05(text: bytes, key: bytes) -> bytes:
    cipher = xor_byte_arrays(text, key)

    return cipher


if __name__ == "__main__":
    res = challenge05(TEXT, KEY)

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
