#!/usr/bin/python3

import base58
import binascii


class Base58Check:

    @staticmethod
    def b58encode(data) -> str:
        return base58.b58encode(binascii.a2b_hex(data)).decode()

    @staticmethod
    def b58decode(data) -> bytes:
        return binascii.b2a_hex(base58.b58decode(data))


if __name__ == "__main__":
    a = Base58Check()
    print(a.b58encode(b'003c'))
    print(a.b58decode("123"))
