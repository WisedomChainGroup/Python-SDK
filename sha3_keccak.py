#!/usr/bin/python3

from _pysha3 import keccak_256
import binascii


class Sha3Keccack:

    def __init__(self):
        self.k = keccak_256()

    def calculate_hash(self, value: bytes) -> bytes:
        self.k.update(value)
        sk = self.k.hexdigest()
        return binascii.a2b_hex(sk)


if __name__ == '__main__':
    k = keccak_256()
    k.update('age'.encode("utf8"))
    sks = k.hexdigest()
    a = binascii.a2b_hex(sks)
