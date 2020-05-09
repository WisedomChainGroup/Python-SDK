#!/usr/bin/python3

import nacl.encoding
import nacl.signing
import binascii
import hashlib
from nacl.public import PrivateKey, PublicKey, Box

class Ed25519PrivateKey:
    def __init__(self, privateKey):
        self._privateKey = privateKey

    def sign(self, msg):
        return msg.sign("0".encode("utf8"))


if __name__ == '__main__':
    sks = binascii.a2b_hex("9a90128b52960688cc67ba76a04088aa90525c35abc2282acfa72f6c0eedef5f")
    sk = nacl.signing.SigningKey(sks)
    print(sk)
    s = binascii.b2a_hex(sk.sign("0".encode("utf8")))
    print(s)
