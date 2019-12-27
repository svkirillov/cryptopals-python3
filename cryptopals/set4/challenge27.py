#!/usr/bin/env python3

from typing import Union
from urllib.parse import quote, unquote

from functions.aes import AESCipher, gen_random_bytes, pkcs7_unpad, pkcs7_pad
from functions.xor import xor_byte_arrays


_KEY = gen_random_bytes(16)
_cbc = AESCipher(AESCipher.MODE_CBC, _KEY, iv=_KEY)


def _parse_cookie(string: str) -> dict:
    return {k: unquote(v) for k, v in [s.split("=", 1) for s in string.split(";")]}


def _get_token(user_data: str) -> bytes:
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    token = prefix + quote(user_data) + suffix

    return _cbc.encrypt(pkcs7_pad(token.encode("latin")))


def _is_admin(token: bytes) -> Union[bool, Exception]:
    # decrypted_token = pkcs7_unpad(_cbc.decrypt(token))
    decrypted_token = _cbc.decrypt(token)

    try:
        decoded_token = decrypted_token.decode("ascii")
    except:
        raise Exception(decrypted_token) from None

    cookie = _parse_cookie(decoded_token)

    if cookie.get("admin", False) == "true":
        return True
    else:
        return False


def _attacker() -> bytes:
    token = _get_token("")
    new_token = token[:16] + bytes([0]) * 16 + token[:16]

    try:
        _is_admin(new_token)
    except Exception as e:
        decrypted = e.args[0]

    key = xor_byte_arrays(decrypted[:16], decrypted[32:])

    return key


def challenge27() -> bool:
    return _attacker() == _KEY


if __name__ == "__main__":
    assert challenge27(), "The result does not match the expected value"

    print("Ok")
