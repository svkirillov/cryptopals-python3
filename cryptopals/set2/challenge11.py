#!/usr/bin/env python3

import random
from typing import Tuple

from functions.aes import AESCipher, pkcs7_pad, get_blocks, gen_random_bytes


def _encryption_oracle(bytes_: bytes) -> Tuple[bytes, str]:
    key = gen_random_bytes(16)
    iv = gen_random_bytes(16)
    prefix = gen_random_bytes(random.randint(5, 10))
    suffix = gen_random_bytes(random.randint(5, 10))
    pt = prefix + bytes_ + suffix

    cbc_mode = random.choice([True, False])

    if cbc_mode:
        cbc = AESCipher(AESCipher.MODE_CBC, key, iv=iv)
        ct = cbc.encrypt(pkcs7_pad(pt))
        answer = "cbc"
    else:
        ecb = AESCipher(AESCipher.MODE_ECB, key)
        ct = ecb.encrypt(pkcs7_pad(pt))
        answer = "ecb"

    return ct, answer


def challenge11() -> bool:
    pt = bytes(gen_random_bytes(1) * random.randint(100, 200))
    ct, answer = _encryption_oracle(pt)
    blocks = get_blocks(ct)
    unique_blocks = len(set(blocks))

    guess = "cbc" if len(blocks) == unique_blocks else "ecb"

    return True if guess == answer else False


if __name__ == "__main__":
    for _ in range(100):
        assert challenge11(), "The result does not match the expected value"

    print("Ok")
