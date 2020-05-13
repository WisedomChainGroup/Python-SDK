#!/usr/bin/python3

from cryptography.fernet import Fernet
import nacl.signing
import nacl.bindings
from nacl.utils import StringFixer, random
import binascii

class KdfParams:
    def __init__(self, memory_cost: int = 0, time_cost: int = 0, parallelism: int = 0, salt: str = ''):
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism
        self.salt = salt


class Crypto:
    def __init__(self, cipher: str = '', cipher_text: str = '', cipher_params: str = ''):
        self.cipher = cipher
        self.cipher_text = cipher_text
        self.cipher_params = cipher_params


class KeyStore:
    def __init__(self, address: str = '', id: str = '', version: str = '2', mac: str = '', kdf: str = 'argon2id'):
        self.address = address
        self.crypto = Crypto()
        self.id = id
        self.version = version
        self.mac = mac
        self.kdf = kdf
        self.kdf_params = KdfParams()


class KeyPair:
    def __init__(self):
        self.seed = random(nacl.bindings.crypto_sign_SEEDBYTES)
        self.secret_key = binascii.b2a_hex(self.seed)
        self.public, self.signing_key = nacl.bindings.crypto_sign_seed_keypair(self.seed)
        self.public_key = binascii.b2a_hex(self.public)


if __name__ == '__main__':
    seed = random(nacl.bindings.crypto_sign_SEEDBYTES)
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    print(signing_key)
    print(verify_key)
    print(binascii.b2a_hex(seed))
    public_key, secret_key = nacl.bindings.crypto_sign_seed_keypair(seed)
    print(binascii.b2a_hex(public_key))
    print(binascii.b2a_hex(secret_key))
