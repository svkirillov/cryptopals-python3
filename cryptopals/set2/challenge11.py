#!/usr/bin/env python3

import random
from typing import Tuple

from functions import aes


def _encryption_oracle(bytes_: bytes) -> Tuple[bytes, str]:
    key = aes.gen_random_bytes(16)
    iv = aes.gen_random_bytes(16)
    prefix = aes.gen_random_bytes(random.randint(5, 10))
    suffix = aes.gen_random_bytes(random.randint(5, 10))
    pt = prefix + bytes_ + suffix

    cbc_mode = random.choice([True, False])

    ct = aes.aes_cbc_encrypt(pt, key, iv) if cbc_mode else aes.aes_ecb_encrypt(pt, key)
    answer = "cbc" if cbc_mode else "ecb"

    return ct, answer


def challenge11() -> bool:
    pt = bytes(aes.gen_random_bytes(1) * random.randint(100, 200))
    ct, answer = _encryption_oracle(pt)
    blocks = aes.get_blocks(ct)
    unique_blocks = len(set(blocks))

    guess = "cbc" if len(blocks) == unique_blocks else "ecb"

    return True if guess == answer else False


if __name__ == "__main__":
    for _ in range(100):
        assert challenge11(), "The result does not match the expected value"

    print("Ok")
