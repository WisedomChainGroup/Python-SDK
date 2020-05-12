#!/usr/bin/python3

from _pysha3 import keccak_256
from utils import Utils
from sha3_keccak import Sha3Keccack
from base58_check import Base58Check


class KeystoreUtils:

    @staticmethod
    def pubkey_to_address(pubkey: bytes) -> str:
        r = s[start:count + start]
        return r

    @staticmethod
    def pubkey_hash_to_address(public_hash: bytes) -> str:
        sha = Sha3Keccack()
        r1 = public_hash
        r2 = Utils.prepend(r1, bytes(1))
        r3 = sha.calculate_hash(sha.calculate_hash(r1))
        b4 = Utils.byte_array_copy(r3, 0, 4)
        b5 = r2 + b4
        s6 = "WX" + Base58Check.Encode(b5)
        return s6
