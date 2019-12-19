#!/usr/bin/env python3

import pathlib


class TestSet3:
    def test_challenge17(self):
        from cryptopals.set3.challenge17 import challenge17

        assert challenge17(), "The result does not match the expected value"

    def test_challenge18(self):
        from cryptopals.set3.challenge18 import challenge18

        assert challenge18(), "The result does not match the expected value"

    def test_challenge19(self):
        from cryptopals.set3.challenge19 import challenge19

        assert challenge19(), "The result does not match the expected value"

    def test_challenge20(self):
        from cryptopals.set3.challenge20 import challenge20

        assert challenge20(
            pathlib.Path(__file__).absolute().parent.parent / "data" / "20.txt"
        ), "The result does not match the expected value"
