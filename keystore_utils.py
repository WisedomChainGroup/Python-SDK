#!/usr/bin/python3

from utils import Utils
from sha3_keccak import Sha3Keccack
from base58_check import Base58Check
from Crypto.Hash import RIPEMD160
import binascii


class KeystoreUtils:

    @staticmethod
    def pubkey_to_address(pubkey: bytes) -> str:
        sha = Sha3Keccack()
        pub256 = sha.calculate_hash(pubkey)
        h = RIPEMD160.new()
        h.update(pub256)
        r1 = h.hexdigest()
        return KeystoreUtils().pubkey_hash_to_address(r1.encode())

    @staticmethod
    def pubkey_hash_to_address(public_hash: bytes) -> str:
        sha = Sha3Keccack()
        r1 = public_hash
        r2 = Utils.prepend(r1, binascii.b2a_hex(bytes(1)))
        r3 = binascii.b2a_hex(sha.calculate_hash(sha.calculate_hash(r1)))
        b4 = Utils.byte_array_copy(r3, 0, 4)
        b5 = r2 + b4
        s6 = "WX" + Base58Check.b58encode(b5)
        return s6


if __name__ == '__main__':
    a = KeystoreUtils()
    pub_key = b"9283f26b45adb774d29106c59faa6de5209ebad5278920fc26ed8d76e4c5e340"
    adress = a.pubkey_to_address(pub_key)
    print(adress)
