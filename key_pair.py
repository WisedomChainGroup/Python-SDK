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


class Keystore:
    def __init__(self, address: str = '', id: str = '', version: str = '', mac: str = '', kdf: str = ''):
        self.address = address
        self.crypto = Crypto()
        self.id = id
        self.version = version
        self.mac = mac
        self.kdf = kdf
        self.kdf_params = KdfParams()


class KeyPair:
    def generateEd25519KeyPair(self):
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(b"A really secret message. Not for prying eyes.")
        return token


if __name__ == '__main__':
    seed = random(nacl.bindings.crypto_sign_SEEDBYTES)
    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    print(signing_key)
    print(verify_key)
    public_key, secret_key = nacl.bindings.crypto_sign_seed_keypair(seed)
    # signing_key1 = nacl.signing.SigningKey(seed, encoder=nacl.encoding.HexEncoder)
    print(seed)
    print(secret_key)
    signing_key1 = binascii.unhexlify(secret_key) # binascii.hexlify(secret_key)
    print(b'signing_key1:' + signing_key1)
    # print(len(public_key), type(public_key), public_key, len(secret_key), type(secret_key), secret_key)
    hex_key = public_key.encode(encoder=nacl.encoding.HexEncoder)
    print('hex_key:' + hex_key)

    #a = KeyPair()
    #print(a.generateEd25519KeyPair())
