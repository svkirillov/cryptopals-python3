#!/usr/bin/env python3


class TestSet3:
    def test_challenge17(self):
        from cryptopals.set3.challenge17 import challenge17

        assert challenge17(), "The result does not match the expected value"

    def test_challenge18(self):
        from cryptopals.set3.challenge18 import challenge18

        assert challenge18(), "The result does not match the expected value"
