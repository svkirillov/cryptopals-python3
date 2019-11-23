#!/usr/bin/env python3

from functions.xor import xor_byte_arrays


BYTES_A = bytes.fromhex("1c0111001f010100061a024b53535009181c")
BYTES_B = bytes.fromhex("686974207468652062756c6c277320657965")
RESULT = bytes.fromhex("746865206b696420646f6e277420706c6179")


def challenge02(first: bytes, second: bytes) -> bytes:
    return xor_byte_arrays(first, second)


if __name__ == "__main__":
    res = challenge02(BYTES_A, BYTES_B)

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
