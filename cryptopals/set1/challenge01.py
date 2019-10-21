#!/usr/bin/env python3

import base64


BYTES = bytes.fromhex(
    "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
)

RESULT = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


def challenge01(hex_string: bytes) -> str:
    return base64.b64encode(hex_string)


if __name__ == "__main__":
    res = challenge01(BYTES)

    assert res == RESULT, "The result does not match the expected value"

    print("Ok")
