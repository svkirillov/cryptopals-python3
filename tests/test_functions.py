#!/usr/bin/env python3

import random

from Crypto.Cipher import AES
from Crypto.Util import Padding

from functions import xor, aes


class TestFunctions:
    def test_hamming(self):
        a = bytes("this is a test".encode("ascii"))
        b = bytes("wokka wokka!!!".encode("ascii"))
        c = xor.hamming(a, b)

        assert c == 37, "The result does not match the expected value"

    def test_pkcs7_padding_add(self):
        a = aes.gen_random_bytes(random.randint(1, 16))
        b = aes.pkcs7_padding_add(a)
        c = Padding.pad(a, 16)

        assert b == c, "The result does not match the expected value"

    def test_pkcs7_padding_add_block(self):
        a = aes.gen_random_bytes()
        b = aes.pkcs7_padding_add(a)
        c = Padding.pad(a, 16)

        assert b == c, "The result does not match the expected value"

    def test_pkcs7_padding_del(self):
        a = aes.gen_random_bytes(random.randint(1, 16))
        b = Padding.pad(a, 16)
        c = aes.pkcs7_padding_del(b)

        assert c == a, "The result does not match the expected value"

    def test_pkcs7_padding_del_block(self):
        a = aes.gen_random_bytes()
        b = Padding.pad(a, 16)
        c = aes.pkcs7_padding_del(b)

        assert c == a, "The result does not match the expected value"

    def test_aes_ecb_encrypt(self):
        plain = aes.gen_random_bytes(random.randint(32, 48))
        key = aes.gen_random_bytes()

        cipher = aes.aes_ecb_encrypt(plain, key)

        ref_aes = AES.new(key, AES.MODE_ECB)
        plain_with_pad = aes.pkcs7_padding_add(plain)
        cipher_ref = ref_aes.encrypt(plain_with_pad)

        assert cipher == cipher_ref, "The result does not match the expected value"

    def test_aes_ecb_decrypt(self):
        plain = aes.gen_random_bytes(random.randint(32, 48))
        key = aes.gen_random_bytes()

        ref_aes = AES.new(key, AES.MODE_ECB)
        plain_with_pad = aes.pkcs7_padding_add(plain)
        cipher = ref_aes.encrypt(plain_with_pad)

        pt = aes.aes_ecb_decrypt(cipher, key)

        assert pt == plain, "The result does not match the expected value"

    def test_aes_cbc_encrypt(self):
        plain = aes.gen_random_bytes(random.randint(32, 48))
        key = aes.gen_random_bytes()
        iv = aes.gen_random_bytes()

        cipher = aes.aes_cbc_encrypt(plain, key, iv)

        ref_aes = AES.new(key, AES.MODE_CBC, iv)
        plain_with_pad = aes.pkcs7_padding_add(plain)
        cipher_ref = ref_aes.encrypt(plain_with_pad)

        assert cipher == cipher_ref, "The result does not match the expected value"

    def test_aes_cbc_decrypt(self):
        plain = aes.gen_random_bytes(random.randint(32, 48))
        key = aes.gen_random_bytes()
        iv = aes.gen_random_bytes()

        ref_aes = AES.new(key, AES.MODE_CBC, iv)
        plain_with_pad = aes.pkcs7_padding_add(plain)
        cipher = ref_aes.encrypt(plain_with_pad)

        pt = aes.aes_cbc_decrypt(cipher, key, iv)

        assert pt == plain, "The result does not match the expected value"
