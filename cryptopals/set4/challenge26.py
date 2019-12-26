#!/usr/bin/env python3

from urllib.parse import quote, unquote

from functions.xor import xor_byte_arrays
from functions.aes import AESCipher, gen_random_bytes, pkcs7_unpad, pkcs7_pad


_cbc = AESCipher(AESCipher.MODE_CBC, gen_random_bytes(16), iv=gen_random_bytes(16))


def _parse_cookie(string: str) -> dict:
    return {k: unquote(v) for k, v in [s.split("=", 1) for s in string.split(";")]}


def _get_token(user_data: str) -> bytes:
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    token = prefix + quote(user_data) + suffix

    return _cbc.encrypt(pkcs7_pad(token.encode("latin")))


def _is_admin(token: bytes) -> bool:
    decrypted_token = pkcs7_unpad(_cbc.decrypt(token))
    cookie = _parse_cookie(decrypted_token.decode("latin"))

    if cookie.get("admin", False) == "true":
        return True
    else:
        return False


def _attacker() -> bytes:
    # A <-> ;   |   hex(ord("A") ^ ord(";")) = '0x7a'
    # B <-> =   |   hex(ord("B") ^ ord("=")) = '0x7f'
    data = "a" * 16 + "AadminBtrueAabBa"
    token = _get_token(data)
    ct_block = token[32:48]
    bitflip_block = b"\x7a\x00\x00\x00\x00\x00\x7f\x00\x00\x00\x00\x7a\x00\x00\x7f\x00"
    fixed_block = xor_byte_arrays(bitflip_block, ct_block)
    fixed_token = token[:32] + fixed_block + token[48:]

    return fixed_token


def challenge16() -> bool:
    return _is_admin(_attacker())


if __name__ == "__main__":
    assert challenge16(), "The result does not match the expected value"

    print("Ok")
