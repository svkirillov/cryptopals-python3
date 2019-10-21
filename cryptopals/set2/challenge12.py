#!/usr/bin/env python3

import base64
from typing import Tuple

from functions import aes

RESULT = b"""Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
"""

_SECRET = base64.b64decode(
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)
_KEY = aes.gen_random_bytes(16)


def _encrypt_it(bytes_: bytes) -> bytes:
    pt = bytes_ + _SECRET
    ct = aes.aes_ecb_encrypt(pt, _KEY)

    return ct


def _get_info() -> Tuple[int, int]:
    length_without_padding = len(_encrypt_it(bytes()))
    length_with_padding = length_without_padding

    padding = bytes()

    while length_with_padding == length_without_padding:
        padding += b"\x00"
        length_with_padding = len(_encrypt_it(padding))

    block_size = length_with_padding - length_without_padding

    if len(padding) < block_size:
        data_len = length_without_padding - len(padding)
    else:
        data_len = length_without_padding - block_size

    return block_size, data_len


def challenge12() -> bytes:
    block_size, data_len = _get_info()
    data_num_block = data_len // block_size + (data_len % block_size > 0)

    padding = b"\x00" * data_num_block * block_size
    data_block = b"\x00" * block_size

    data = bytes()

    while len(data) < data_len:
        padding = padding[1:]
        data_block = data_block[1:]

        possible_blocks = {
            _encrypt_it(data_block + bytes([i]))[:block_size]: data_block + bytes([i])
            for i in range(256)
        }

        ct = _encrypt_it(padding)[
            (data_num_block - 1) * block_size : data_num_block * block_size
        ]

        for pb in possible_blocks.items():
            if pb[0] == ct:
                byte = bytes([pb[1][block_size - 1]])
                data_block += byte
                data += byte
                break

    return data


if __name__ == "__main__":
    res = challenge12()

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
