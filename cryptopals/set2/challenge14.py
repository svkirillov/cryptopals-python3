#!/usr/bin/env python3

import base64
import random
from typing import Tuple

from functions.aes import (
    AESCipher,
    gen_random_bytes,
    get_blocks,
    pkcs7_pad,
)


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
_PREFIX = gen_random_bytes(random.randint(1, 70))
_ecb = AESCipher(AESCipher.MODE_ECB, gen_random_bytes(16))


def _encrypt_it(bytes_: bytes) -> bytes:
    pt = _PREFIX + bytes_ + _SECRET
    ct = _ecb.encrypt(pkcs7_pad(pt))

    return ct


def _get_info() -> Tuple[int, int, int]:
    length_without_padding = len(_encrypt_it(bytes()))

    # Search block size
    padding = bytes()
    length_with_padding = length_without_padding

    while length_with_padding == length_without_padding:
        padding += b"\x00"
        length_with_padding = len(_encrypt_it(padding))

    block_size = length_with_padding - length_without_padding
    data_pad_len = len(padding)

    # Get prefix length in blocks
    prefix_num_block = 0
    padding = b"\x00" * block_size * 3
    encrypted_data_blocks = get_blocks(_encrypt_it(padding))
    for i in range(len(encrypted_data_blocks) - 1):
        if encrypted_data_blocks[i] == encrypted_data_blocks[i + 1]:
            prefix_num_block = i
            break

    # Get prefix padding
    padding = b"\x00" * block_size * 2
    while True:
        encrypted_data_blocks = get_blocks(_encrypt_it(padding))

        if (
            encrypted_data_blocks[prefix_num_block]
            == encrypted_data_blocks[prefix_num_block + 1]
        ):
            break

        padding += b"\x00"

    # Calculate prefix length and data length
    prefix_len = prefix_num_block * block_size - (len(padding) - block_size * 2)
    data_len = length_without_padding - data_pad_len - prefix_len

    return block_size, prefix_len, data_len


def challenge14() -> bytes:
    block_size, prefix_len, data_len = _get_info()
    prefix_num_block = prefix_len // block_size + (prefix_len % block_size > 0)
    secret_num_block = data_len // block_size + (data_len % block_size > 0)
    oracle_block = prefix_num_block + secret_num_block - 1

    prefix_padding = b"\x00" * (prefix_num_block * block_size - prefix_len)
    padding = b"\x00" * (
        prefix_num_block * block_size - prefix_len + secret_num_block * block_size
    )
    data_block = b"\x00" * block_size

    data = bytes()

    while len(data) < data_len:
        padding = padding[1:]
        data_block = data_block[1:]

        possible_blocks = {
            _encrypt_it(prefix_padding + data_block + bytes([i]))[
                prefix_num_block * block_size : (prefix_num_block + 1) * block_size
            ]: (data_block + bytes([i]))
            for i in range(256)
        }

        ct = _encrypt_it(padding)[
            oracle_block * block_size : (oracle_block + 1) * block_size
        ]

        for pb in possible_blocks.items():
            if pb[0] == ct:
                byte = bytes([pb[1][block_size - 1]])
                data_block += byte
                data += byte
                break

    return data


if __name__ == "__main__":
    res = challenge14()

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
