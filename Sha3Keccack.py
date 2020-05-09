#!/usr/bin/python3

from _pysha3 import keccak_256
import binascii

class Sha3Keccack:

    def keccak256(self, msg):
        k = keccak_256()
        k.update(msg)
        sks = k.hexdigest()
        a = binascii.a2b_hex(sks)
        return a

if __name__ == '__main__':
    k = keccak_256()
    k.update('age'.encode("utf8"))
    sks = k.hexdigest()
    a = binascii.a2b_hex(sks)


