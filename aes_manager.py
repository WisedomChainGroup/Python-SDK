#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pyaes
import pbkdf2
import secrets
import os
import binascii
import pyscrypt

MODEL = AES.MODE_CTR


class AesManager:

    @staticmethod
    def ecrypt_data(plain: bytes, key: bytes, iv: bytes) -> bytes:
        aes = pyaes.AESModeOfOperationCTR(key)
        ciphertext = aes.encrypt(plain)
        return ciphertext

    @staticmethod
    def decrypt_data(encrypted: bytes, key: bytes, iv: bytes) -> bytes:
        aes = pyaes.AESModeOfOperationCTR(key)
        plain = aes.decrypt(encrypted)
        return plain

if __name__ == '__main__':
    a = AesManager()
    pk = '69bc24521d3958a965c1138900cd9e151870c046cbb89fdbe20b81750f143be7'
    iv = '4ed36217f5c2e65dc1b35591e8208763'
    salt = 'b3ae9b3baa1f2fe9cb06f5573a770c17b611a1751e1245e7563efaad8899222d'
    password = "22222222"
    hashed = pyscrypt.hash(password=b"22222222", salt=b'b3ae9b3baa1f2fe9cb06f5573a770c17b611a1751e1245e7563efaad8899222d', N=1024, r=1, p=1, dkLen=32)
    print(binascii.b2a_hex(hashed).decode())
    print(pbkdf2.crypt(b"22222222"))
    derived_key = pbkdf2.PBKDF2(password, salt).read(32)
    print("derived_key:", binascii.b2a_hex(derived_key).decode())
    cipher_privKey = a.ecrypt_data(pk, derived_key, iv)
    print("cipher_privKey:", binascii.b2a_hex(cipher_privKey).decode())


