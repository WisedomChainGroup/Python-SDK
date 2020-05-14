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
            raise ret.cipher + " not supported"
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
    def from_dict(cls, d: dict):
        a = cls()
        a.address = d["address"]
        a.id = d["id"]
        a.version = d["version"]
        a.mac = bytes.fromhex(d["mac"])
        a.kdf = d["kdf"]
        a.crypto = Crypto.from_dict(d["crypto"])
        a.kdf_params = KdfParams.from_dict(d["kdfparams"])
        return a

    @classmethod
    def from_json(cls, data: str):
        d = json.loads(data)
        return cls.from_dict(d)

    @classmethod
    def create_key_store(cls, password: str):
        sk, pk = Utils.ed25519_keypair()
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
    print(KeyStore.create_key_store("00000000").as_dict())
    a = """
{
    "address": "WX12t3nAs9FshfT1jsWNvGJEZq7UBD1ym2Ei",
    "kdfparams": {
        "salt": "ec3932e9c96483ad99d752de8aa15f5bc57a3ee15e7165ce66aa14df699098d7",
        "memoryCost": 20480,
        "parallelism": 2,
        "timeCost": 4
    },
    "id": "377b4eae-32d8-4b7f-a475-2ecaae162ec4",
    "kdf": "argon2id",
    "version": "2",
    "mac": "be8e52b318ee69ed3ab4e88719da3cde9c46f883dca5a134b6580ededd036b99",
    "crypto": {
        "cipher": "aes-256-ctr",
        "ciphertext": "12dfd5e07430afbb50c60317a531376b869b5cfa2f5eb33f480d14fded8b9606",
        "cipherparams": {
            "iv": "bfc8af56f4e701ecfaddb0c06f7bc915"
        }
    }
}    
    """
    print(json.dumps(KeyStore.from_json(a).as_dict()))
