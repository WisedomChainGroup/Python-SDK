#!/usr/bin/python3
from typing import Tuple

import nacl.bindings
import nacl.signing
from nacl.utils import random


class CipherParams:
    def __init__(self, iv: str = ''):
        self.iv = iv


class KdfParams:
    def __init__(self, memory_cost: int = 0, time_cost: int = 0, parallelism: int = 0, salt: str = ''):
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism
        self.salt = salt


class Crypto:
    def __init__(self, cipher: str = '', cipher_text: str = '', iv: str = ''):
        self.cipher = cipher
        self.cipher_text = cipher_text
        self.cipher_params = CipherParams(iv).__dict__


class KeyStore:
    def __init__(self, address: str = '', id: str = '', version: str = '2', mac: str = '', kdf: str = 'argon2id'):
        self.address = address
        self.crypto = Crypto()
        self.id = id
        self.version = version
        self.mac = mac
        self.kdf = kdf
        self.kdf_params = KdfParams()

    def parse(self, password: str) -> bytes:
        pass

    def getJson(self) -> str:
        pass
    
    @classmethod
    def createKeyStore(cls, password: str) :
        return cls()

    @classmethod
    def fromJson(cls, data: str) :
        return cls()

class KeyPair:

    @staticmethod
    def get_key() -> Tuple[bytes, bytes]:
        seed = random(nacl.bindings.crypto_sign_SEEDBYTES)
        secret_key = seed
        public, _ = nacl.bindings.crypto_sign_seed_keypair(seed)
        return secret_key, public


if __name__ == '__main__':
    # seed = random(nacl.bindings.crypto_sign_SEEDBYTES)
    # signing_key = nacl.signing.SigningKey.generate()
    # verify_key = signing_key.verify_key
    # print(signing_key)
    # print(verify_key)
    # print(binascii.b2a_hex(seed))
    # public_key, secret_key = nacl.bindings.crypto_sign_seed_keypair(seed)
    # print(binascii.b2a_hex(public_key))
    # print(binascii.b2a_hex(secret_key))
    s, p = KeyPair.get_key()
    print(s, p)
    KeyStore.createKeyStore("")
