#!/usr/bin/env python3

import pathlib


class TestSet2:
    def test_challenge09(self):
        from cryptopals.set2.challenge09 import challenge09, TEXT, RESULT

        res = challenge09(TEXT, 20)

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge10(self):
        from cryptopals.set2.challenge10 import challenge10, RESULT

        res = challenge10(
            pathlib.Path(__file__).absolute().parent.parent / "data" / "10.txt"
        )

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge11(self):
        from cryptopals.set2.challenge11 import challenge11

        for _ in range(100):
            assert challenge11(), "The result does not match the expected value"

    def test_challenge12(self):
        from cryptopals.set2.challenge12 import challenge12, RESULT

        res = challenge12()

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge13(self):
        from cryptopals.set2.challenge13 import challenge13

        assert challenge13(), "The result does not match the expected value"

    def test_challenge14(self):
        from cryptopals.set2.challenge14 import challenge14, RESULT

        res = challenge14()

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge15(self):
        from cryptopals.set2.challenge15 import challenge15

        assert challenge15(), "The result does not match the expected value"

    def test_challenge16(self):
        from cryptopals.set2.challenge16 import challenge16

        assert challenge16(), "The result does not match the expected value"
