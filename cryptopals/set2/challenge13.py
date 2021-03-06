#!/usr/bin/env python3

from typing import Dict, Union

from functions.aes import gen_random_bytes, AESCipher, pkcs7_pad, pkcs7_unpad


_ecb = AESCipher(AESCipher.MODE_ECB, gen_random_bytes(16))


def _sanitize(s: str) -> str:
    return s.replace("&", "").replace("=", "")


def _parse_cookie(cookie: str) -> Dict[str, Union[int, str]]:
    fields = cookie.split("&")
    items = [tuple(field.split("=")) for field in fields]
    cookie = {key: value for key, value in items}

    return cookie


def _profile_for(email: str) -> str:
    profile = [("email", _sanitize(email)), ("uid", "10"), ("role", "user")]
    cookie = "&".join([k + "=" + v for k, v in profile])

    return cookie


def _oracle(email: str) -> bytes:
    cookie = bytes(_profile_for(email).encode("ascii"))
    encrypted_cookie = _ecb.encrypt(pkcs7_pad(cookie))

    return encrypted_cookie


def _attacker() -> bytes:
    admin_block = _oracle("aaaaaaaaaaadmin" + "\x0b" * 11)[16:32]
    cookie = _oracle("foooo@bar.com")[:32] + admin_block

    return cookie


def challenge13() -> bool:
    cookie = _parse_cookie(pkcs7_unpad(_ecb.decrypt(_attacker())).decode("ascii"))

    if cookie["role"] == "admin":
        return True
    else:
        return False


if __name__ == "__main__":
    assert challenge13(), "The result does not match the expected value"

    print("Ok")
