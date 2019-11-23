#!/usr/bin/env python3

import pathlib

from functions.string_score import calc_score
from functions.xor import xor_byte_arrays, bruteforce_xor_single_byte_key


RESULT = b"Now that the party is jumping"


def challenge04(path: str) -> bytes:
    with open(path) as file:
        ciphers = [bytes.fromhex(line) for line in file.readlines()]

    strings = [
        xor_byte_arrays(cipher, bruteforce_xor_single_byte_key(cipher))
        for cipher in ciphers
    ]
    msg = max(strings, key=calc_score).split(b"\n")

    return msg[0]


if __name__ == "__main__":
    res = challenge04(
        pathlib.Path(__file__).absolute().parent.parent.parent / "data" / "4.txt"
    )

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
