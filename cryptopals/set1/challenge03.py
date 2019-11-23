#!/usr/bin/env python3

from functions.xor import bruteforce_xor_single_byte_key, xor_byte_arrays


CIPHER_TEXT = bytes.fromhex(
    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
)

RESULT = b"Cooking MC's like a pound of bacon"


def challenge03(cipher: bytes) -> bytes:
    key = bruteforce_xor_single_byte_key(cipher)
    msg = xor_byte_arrays(cipher, key)

    return msg


if __name__ == "__main__":
    res = challenge03(CIPHER_TEXT)

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
