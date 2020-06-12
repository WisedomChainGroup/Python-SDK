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

    def parse(self, password: str) -> str:
        argon_hash = Utils.argon2_hash(associated_data=self.kdf_params.salt.hex().encode('ascii') + password.encode('ascii'), salt=self.kdf_params.salt.hex().encode('ascii'))
        sk = Utils.decrypt_data(self.crypto.cipher_text, argon_hash, self.crypto.cipher_params.iv)
        aes = Utils.encrypt_data(sk, argon_hash, self.crypto.cipher_params.iv)
        mac = Utils.keccak256(argon_hash + aes)
        if mac != self.mac:
            raise BaseException('invalid password verify failed')
        return sk.hex()

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
        if len(password) < 8 or len(password) > 20:
            raise BaseException('password len not from 8 to 20')
        sk, pk = Utils.ed25519_keypair(sk)
        salt = Utils.random_bytes(32)
        iv = Utils.random_bytes(16)
        argon_hash = Utils.argon2_hash(associated_data=salt.hex().encode('ascii') + password.encode('ascii'), salt=salt.hex().encode('ascii'))
        address = Utils.pubkey_to_address(pk)
        aes = Utils.encrypt_data(sk, argon_hash, iv)
        mac = Utils.keccak256(argon_hash + aes)
        key_store = KeyStore(address=address, id=Utils.generate_uuid(), mac=mac)
        key_store.crypto = Crypto(cipher_text=aes, iv=iv)
        key_store.kdf_params = KdfParams(salt=salt)
        return key_store

    @staticmethod
    def get_address_from_pubkey_hash(public_hash: str) -> str:
        """
        convert public key hash to address
        :param public_hash:
        :return:
        """
        public_hash_bytes = bytes.fromhex(public_hash)
        address = Utils.pubkey_hash_to_address(public_hash_bytes)
        return address

    @staticmethod
    def get_pubkey_hash_from_address(address: str) -> str:
        """
        convert address to public key hash
        :param address:
        :return:
        """
        pubkey_hash = Utils.address_to_pubkey_hash(address)
        return pubkey_hash.hex()

    @staticmethod
    def get_pk_from_sk(sk: str) -> str:
        sk_bytes = bytes.fromhex(sk)
        pk = Utils.ed25519_keypair(sk_bytes)
        return pk[1].hex()


if __name__ == '__main__':
    a = """ {
"address":"WX1HbnUXUXYfEnsqe2Rkd2Xoqw5Rns1xHv2F",
"kdfparams":{"salt":"1f696b3c6c475572cd9d52b886c9a940e243f1dcc42c75072d8c72cffaaa7e11","memoryCost":20480,"parallelism":2,"timeCost":4},
"id":"d60794af-a68e-4a01-b307-32971cad2835",
"kdf":"argon2id",
"version":"2",
"mac":"5c3f7957075edcf93b6d2d0aa6d464f01f2931a7113886d57479eee52f19efe5",
"crypto":{"cipher":"aes-256-ctr","ciphertext":"f7e212e182a34ce27b02ca207c9c04a7ad12d6d414ec91856cd8a45123384908","cipherparams":{"iv":"fb03038ffe85bf70398fc1e445026d3b"}}
}
    """
    key_store = KeyStore.create_key_store("00000000")
    print(key_store.as_dict())
    keystore = KeyStore.from_json(a)
    sk = keystore.parse("12345678")
    print(sk.hex())
    pubkey_hash = Utils.address_to_pubkey_hash('WX1GPpYX1gPSkcuemo9CkHMQabjWnVnoHJPT')
    print(pubkey_hash)
    sk, pk = Utils.ed25519_keypair(sk)
    print(pk.hex())
    address = Utils.get_address_from_pubkey_hash(pubkey_hash.hex())
    print(address)
