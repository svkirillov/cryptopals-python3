#!/usr/bin/env python3

from functions import aes
from functions.aes import PKCS7BadPadding


def challenge15() -> bool:
    GOOD = b"ICE ICE BABY\x04\x04\x04\x04"
    BAD_1 = b"ICE ICE BABY\x05\x05\x05\x05"
    BAD_2 = b"ICE ICE BABY\x01\x02\x03\x04"
    RESULT = b"ICE ICE BABY"

    flag = True

    if aes.pkcs7_padding_del(GOOD) != RESULT:
        flag = False

    try:
        aes.pkcs7_padding_del(BAD_1)
    except PKCS7BadPadding:
        pass
    else:
        flag = False

    try:
        aes.pkcs7_padding_del(BAD_2)
    except PKCS7BadPadding:
        pass
    else:
        flag = False

    return flag


if __name__ == "__main__":
    assert challenge15(), "The result does not match the expected value"

    print("Ok")
