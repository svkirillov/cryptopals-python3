#!/usr/bin/env python3

import base64
import pathlib

from functions.aes import AESCipher, gen_random_bytes
from functions.xor import rank_xor_single_byte_key, xor_byte_arrays


_KEY = gen_random_bytes(16)
_NONCE = b"\x00" * 8

_FIX_MAP = {
    0: 3,
    101: 4,
    103: 5,
    105: 2,
    107: 3,
    108: 10,
    109: 1,
    111: 18,
    112: 15,
    113: 3,
    114: 2,
    115: 7,
    116: 15,
    117: 35,
}


def challenge20(path: str) -> bool:
    with open(path) as f:
        lines = f.readlines()

    plain_texts = [base64.b64decode(s) for s in lines]

    secrets = []

    for i in range(len(plain_texts)):
        ctr = AESCipher(AESCipher.MODE_CTR, _KEY, nonce=_NONCE)
        secrets.append(ctr.encrypt(plain_texts[i]))

    max_len = max(len(s) for s in secrets)

    keystream = bytearray()

    for i in range(max_len):
        i = len(keystream)
        char_chain = bytes([s[i] for s in secrets if len(s) > i])
        possible_keys = rank_xor_single_byte_key(char_chain)
        key_byte = possible_keys[_FIX_MAP.get(i, 0)]
        keystream += key_byte

    pt = [xor_byte_arrays(s, keystream) for s in secrets]

    if pt == plain_texts:
        return True

    return False


if __name__ == "__main__":
    assert challenge20(
        pathlib.Path(__file__).absolute().parent.parent.parent / "data" / "20.txt"
    ), "The result does not match the expected value"

    print("Ok")
