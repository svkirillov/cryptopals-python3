#!/usr/bin/env python3

from math import floor

from functions.aes import AESCipher, pkcs7_unpad
from functions.dh import DHClient
from functions.sha1 import sha1


def challenge34() -> bool:
    p = int.from_bytes(
        bytes.fromhex(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
            "fffffffffffff"
        ),
        "big",
    )
    g = 2

    msg = b"test"

    a = DHClient(p, g)
    b = DHClient(a.p, a.g)

    a.gen_session_key(b.p)
    b.gen_session_key(a.p)

    a_encrypted_msg = a.encrypt_msg(msg)
    b_encrypted_msg = b.encrypt_msg(msg)

    a_decrypted_msg = a.decrypt_msg(*b_encrypted_msg)
    b_decrypted_msg = b.decrypt_msg(*a_encrypted_msg)

    key = 0
    key = sha1(key.to_bytes(floor(key.bit_length() / 8) + 1, "big"))[:16]
    iv = a_encrypted_msg[0]

    cbc = AESCipher(AESCipher.MODE_CBC, key, iv=iv)

    mitm_decrypted = pkcs7_unpad(cbc.decrypt(a_encrypted_msg[1]))

    return mitm_decrypted == a_decrypted_msg == b_decrypted_msg == msg


if __name__ == "__main__":
    assert challenge34(), "The result does not match the expected value"

    print("Ok")
