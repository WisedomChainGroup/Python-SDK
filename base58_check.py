#!/usr/bin/python3

import base58


class Base58Check:

    @staticmethod
    def b58encode(data: str) -> bytes:
        return base58.b58encode(data)

    @staticmethod
    def b58decode(data: bytes) -> str:
        return base58.b58decode(data).decode()


if __name__ == "__main__":
    a = Base58Check()
    print(a.b58encode("hello world"))
    print(a.b58decode(b"StV1DL6CwTryKyV"))
