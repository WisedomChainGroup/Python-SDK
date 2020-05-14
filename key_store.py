#!/usr/bin/python3
from typing import Tuple

import nacl.bindings
import nacl.signing
from nacl.utils import random

from utils import Utils


class CipherParams:
    def __init__(self, iv: bytes = b''):
        self.iv = iv


class KdfParams:
    def __init__(self, memory_cost: int = 20480, time_cost: int = 4, parallelism: int = 2, salt: bytes = b''):
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism
        self.salt = salt

    def as_dict(self) -> dict:
        return {
            "salt": self.salt.hex(),
            "memoryCost": self.memory_cost,
            "parallelism": self.parallelism,
            "timeCost": self.time_cost
        }


class Crypto:
    def __init__(self, cipher: str = 'aes-256-ctr', cipher_text: bytes = b'', iv: bytes = b''):
        self.cipher = cipher
        self.cipher_text = cipher_text
        self.cipher_params = CipherParams(iv)

    def as_dict(self) -> dict:
        return {
            "cipher": "aes-256-ctr",
            "ciphertext": self.cipher_text.hex(),
            "cipherparams": {
                "iv": self.cipher_params.iv.hex()
            }
        }


class KeyStore:
    def __init__(self, address: str = '', id: str = '', version: str = '2', mac: bytes = b'', kdf: str = 'argon2id'):
        self.address = address
        self.crypto = Crypto()
        self.id = id
        self.version = version
        self.mac = mac
        self.kdf = kdf
        self.kdf_params = KdfParams()

    def parse(self, password: str) -> bytes:
        pass

    def as_dict(self) -> dict:
        return {
            "address": self.address,
            "id": self.id,
            "version": self.version,
            "mac": self.mac.hex(),
            "kdfparams": self.kdf_params.as_dict(),
            "crypto": self.crypto.as_dict()
        }

    @classmethod
    def createKeyStore(cls, password: str):
        return cls()

    @classmethod
    def fromJson(cls, data: str):
        return cls()

    @classmethod
    def from_password(cls, password: str):
        sk, pk = Utils.ed25519_keypair()
        salt = Utils.random_bytes(32)
        iv = Utils.random_bytes(16)
        argon_hash = Utils.argon2_hash(associated_data=salt + password.encode(), salt=salt)
        address = Utils.pubkey_to_address(pk)
        aes = Utils.encrypt_data(sk, argon_hash, iv)
        mac = Utils.keccak256(argon_hash + aes)
        key_store = KeyStore(address=address, id=Utils.generate_uuid(), mac=mac)
        key_store.crypto = Crypto(cipher_text=aes, iv=iv)
        key_store.kdf_params = KdfParams()
        return key_store


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
    # print(signing_key )
    # print(verify_key)
    # print(binascii.b2a_hex(seed))
    # public_key, secret_key = nacl.bindings.crypto_sign_seed_keypair(seed)
    # print(binascii.b2a_hex(public_key))
    # print(binascii.b2a_hex(secret_key))
    s, p = KeyPair.get_key()
    print(s, p)
    KeyStore.createKeyStore("")
