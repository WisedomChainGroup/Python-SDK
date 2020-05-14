#!/usr/bin/python3

import uuid

import argon2
import base58
from Crypto.Hash import RIPEMD160
from Crypto.Hash import keccak
from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

MODEL = AES.MODE_CTR

class Utils:
    @staticmethod
    def decode_u32(data: bytes) -> int:
        """
        :param data: big endian byte array
        :return: unsigned integer
        """
        r = int.from_bytes(data, byteorder='big', signed=False)
        return r

    @staticmethod
    def encode_u64(data: int) -> bytes:
        """
        :param data: unsigned integer
        :return: encode as 64 bit big endian bytes
        """
        if data < 0:
            raise str(data) + 'is negative'
        r = data.to_bytes(8, 'big')
        return r

    @staticmethod
    def encode_u32(data: int) -> bytes:
        """
        :param data: unsigned integer
        :return: encode as 32 bit big endian bytes
        """
        if data < 0:
            raise str(data) + 'is negative'
        r = data.to_bytes(4, 'big')
        return r

    @staticmethod
    def encode_u8(data: int) -> bytes:
        """
        :param data: unsigned integer
        :return: encode as 8 bit big endian bytes
        """
        if data < 0:
            raise str(data) + 'is negative'
        r = data.to_bytes(1, 'big')
        return r

    @staticmethod
    def generate_uuid() -> str:
        """
        :return: random uuid
        """
        return str(uuid.uuid1())

    @staticmethod
    def keccak256(data: bytes) -> bytes:
        """
        keccak 256
        :param data: byte array
        :return: keccak 256 digest
        """
        d = keccak.new(digest_bits=256)
        d.update(data)
        return d.digest()

    @staticmethod
    def b58encode(data: bytes) -> str:
        """
        :param data: byte array
        :return: base58 encoding
        """
        return base58.b58encode(data).decode('ascii')

    @staticmethod
    def b58decode(data) -> bytes:
        """
        :param data: base58 encoding string
        :return: byte array
        """
        return base58.b58decode(data)

    @staticmethod
    def argon2_hash(associated_data: bytes, salt: bytes, time_cost: int = 4, memory_cost: int = 20480,
                    parallelism: int = 2, argon_type: argon2.low_level.Type = argon2.low_level.Type.ID) -> bytes:
        """
        :return: key for aes encrypt/decrypt
        """
        return argon2.low_level.hash_secret_raw(secret=associated_data, salt=salt, time_cost=time_cost,
                                                memory_cost=memory_cost,
                                                parallelism=parallelism, hash_len=32, type=argon_type)

    @staticmethod
    def ripmed160(data: bytes) -> bytes:
        h = RIPEMD160.new()
        h.update(data)
        return h.digest()

    @staticmethod
    def pubkey_to_hash(pubkey: bytes) -> bytes:
        return Utils.ripmed160(Utils.keccak256(pubkey))

    @staticmethod
    def pubkey_to_address(pubkey: bytes) -> str:
        ret = Utils.pubkey_to_hash(pubkey)
        return Utils.pubkey_hash_to_address(ret)

    @staticmethod
    def pubkey_hash_to_address(public_hash: bytes) -> str:
        r1 = public_hash
        r2 = bytes(1) + r1
        r3 = Utils.keccak256(Utils.keccak256(r1))
        b4 = r3[0:4]
        b5 = r2 + b4
        s6 = "WX" + Utils.b58encode(b5)
        return s6

    @staticmethod
    def __int_of_string(s):
        return int(binascii.hexlify(s), 16)

    @staticmethod
    def encrypt_data(plain: bytes, key: bytes, iv: bytes) -> bytes:
        ctr = Counter.new(128, initial_value=Utils.__int_of_string(iv))
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        result = aes.encrypt(plain)
        return binascii.b2a_hex(result)

    @staticmethod
    def decrypt_data(encrypted: bytes, key: bytes, iv: bytes) -> bytes:
        ctr = Counter.new(128, initial_value=Utils.__int_of_string(iv))
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        result = aes.decrypt(encrypted)
        return result


if __name__ == '__main__':
    sks = bytes.fromhex("9a90128b52960688cc67ba76a04088aa90525c35abc2282acfa72f6c0eedef5f")
    sk = sks[142: 142 + 4]
    skd = Utils.encode_u64(round(100000 / 200000)).hex()
    print('a', skd)
    print(Utils.encode_u64(255).hex())

    print(Utils.b58encode(bytes.fromhex('003c')))
    print(Utils.b58decode("123").hex())

    password = '00000000'
    sa = '23d0927f83406a2b4593890b8e3775daa13a55905ace27bbdb0ffaaa0bc915e8'
    p = password.encode("ascii")
    s = sa.encode("ascii")
    print(Utils.argon2_hash(s + p, s).hex())

    pub_key = bytes.fromhex("8f194afc6dfe44a95784b14c7ad58e12218987f74bacb3572f8bbb59241572fa")
    adr = Utils.pubkey_to_address(pub_key)
    print(adr)
