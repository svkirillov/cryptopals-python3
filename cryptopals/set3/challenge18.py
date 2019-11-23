#!/usr/bin/env python3

import base64

from functions.aes import AESCipher


def challenge18() -> bool:
    ct = base64.b64decode(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )
    result = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

    key = b"YELLOW SUBMARINE"
    nonce = b"\x00" * 8

    ctr = AESCipher(AESCipher.MODE_CTR, key, nonce=nonce, counter=0)

    res = ctr.decrypt(ct)

    return res == result


if __name__ == "__main__":
    assert challenge18(), "The result does not match the expected value"

    print("Ok")
