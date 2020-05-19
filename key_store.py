#!/usr/bin/python3
import json
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

    @classmethod
    def from_dict(cls, d: dict):
        ret = cls()
        ret.memory_cost = d['memoryCost']
        ret.time_cost = d['timeCost']
        ret.parallelism = d['parallelism']
        ret.salt = bytes.fromhex(d['salt'])
        return ret

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

    @classmethod
    def from_dict(cls, d: dict):
        ret = cls()
        ret.cipher = d['cipher']
        if ret.cipher.lower() != 'aes-256-ctr':
            raise BaseException('cipher %s not supported, please use aes-256-ctr' % ret.cipher)
        ret.cipher_text = bytes.fromhex(d['ciphertext'])
        ret.cipher_params = CipherParams()
        ret.cipher_params.iv = bytes.fromhex(d['cipherparams']['iv'])
        return ret

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
        argon_hash = Utils.argon2_hash(associated_data=self.kdf_params.salt + password.encode(), salt=self.kdf_params.salt)
        sk = Utils.decrypt_data(self.crypto.cipher_text, argon_hash, self.crypto.cipher_params.iv)
        return sk

    def as_dict(self) -> dict:
        return {
            "address": self.address,
            "id": self.id,
            "version": self.version,
            "mac": self.mac.hex(),
            "kdfparams": self.kdf_params.as_dict(),
            "crypto": self.crypto.as_dict(),
            "kdf": self.kdf
        }

    @classmethod
    def from_dict(cls, d: dict):
        a = cls()
        a.address = d["address"]
        a.id = d["id"]
        a.version = d["version"]
        a.mac = bytes.fromhex(d["mac"])
        a.kdf = d["kdf"]
        if a.kdf.lower() != 'argon2id':
            raise BaseException('kdf %s is not supported, please use argon2id ' % a.kdf)
        a.crypto = Crypto.from_dict(d["crypto"])
        a.kdf_params = KdfParams.from_dict(d["kdfparams"])
        return a

    @classmethod
    def from_json(cls, data: str):
        d = json.loads(data)
        return cls.from_dict(d)

    @classmethod
    def create_key_store(cls, password: str, sk: bytes = b''):
        sk, pk = Utils.ed25519_keypair(sk)
        salt = Utils.random_bytes(32)
        iv = Utils.random_bytes(16)
        argon_hash = Utils.argon2_hash(associated_data=salt + password.encode(), salt=salt)
        address = Utils.pubkey_to_address(pk)
        aes = Utils.encrypt_data(sk, argon_hash, iv)
        mac = Utils.keccak256(argon_hash + aes)
        key_store = KeyStore(address=address, id=Utils.generate_uuid(), mac=mac)
        key_store.crypto = Crypto(cipher_text=aes, iv=iv)
        key_store.kdf_params = KdfParams(salt=salt)
        return key_store


class KeyPair:

    @staticmethod
    def get_key() -> Tuple[bytes, bytes]:
        seed = random(nacl.bindings.crypto_sign_SEEDBYTES)
        secret_key = seed
        public, _ = nacl.bindings.crypto_sign_seed_keypair(seed)
        return secret_key, public


if __name__ == '__main__':
    a = """ {"address": "WX1GPpYX1gPSkcuemo9CkHMQabjWnVnoHJPT", 
    "id": "9cf0f3fd-9976-11ea-aa30-04d4c44dc4c5", 
    "version": "2", 
    "mac": "2e513fb52e59e9aca0dee97eb4a0db7844444fa3dc764dc03d3401d026af5770", 
    "kdfparams": {"salt": "6a389d4f1e966835c52710d95eb13491ffc3c1ae329a26a823cc2aef083cce27", 
        "memoryCost": 20480, 
        "parallelism": 2, 
        "timeCost": 4}, 
    "crypto": {"cipher": "aes-256-ctr", 
        "ciphertext": "9dee7d0462e8204140b3bb4585d7f87d54ae0ce34a39d49a441c084eeed4e784", 
        "cipherparams": {"iv": "0c466273542f3982736e516d49e0d07c"}}, 
    "kdf": "argon2id"}
    """
    key_store = KeyStore.create_key_store("00000000")
    print(key_store.as_dict())
    keystore = KeyStore.from_json(a)
    sk = keystore.parse("00000000")
    print(sk.hex())
    pubkey_hash = Utils.address_to_pubkey_hash('WX1GPpYX1gPSkcuemo9CkHMQabjWnVnoHJPT')
    print(pubkey_hash.hex())
    sk, pk = Utils.ed25519_keypair(sk)
    print(pk.hex())
