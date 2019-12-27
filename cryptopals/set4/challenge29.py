#!/usr/bin/env python3

import struct
from random import randint
from typing import Tuple, Optional

from functions.aes import gen_random_bytes
from functions.sha1 import sha1, SHA1KeyedMAC


def _sha1_padding(data: bytes, data_len: Optional[int] = None) -> bytes:
    if data_len is None:
        data_len = len(data) * 8

    data += b"\x80"

    while (len(data) * 8) % 512 != 448:
        data += b"\x00"

    data += struct.pack(">Q", data_len)

    return data


def _attacker(plain_text: bytes, token: bytes) -> Tuple[bytes, bytes]:
    msg = b";admin=true"
    h = struct.unpack(b">5I", token)

    for key_size in range(64):
        fake_msg = _sha1_padding(bytes([0]) * key_size + plain_text)[key_size:] + msg
        fake_token = sha1(msg, h, (key_size + len(fake_msg)) * 8)
        yield (fake_msg, fake_token)


def challenge29() -> bool:
    plain_text = (
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    )

    sha1_keyed = SHA1KeyedMAC(gen_random_bytes(randint(16, 32)))
    token = sha1_keyed.digest(plain_text)

    for (m, t) in _attacker(plain_text, token):
        if sha1_keyed.validate(m, t):
            return True

    return False


if __name__ == "__main__":
    assert challenge29(), "The result does not match the expected value"

    print("Ok")
