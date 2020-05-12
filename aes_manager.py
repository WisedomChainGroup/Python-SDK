#!/usr/bin/python3

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import pyaes
import pbkdf2
import secrets
import os

MODEL = AES.MODE_CTR


class AesManager:

    @staticmethod
    def ecrypt_data(plain: bytes, key: bytes, iv: bytes) -> bytes:
        aes = pyaes.AESModeOfOperationCTR(key, iv)
        ciphertext = aes.encrypt(plain)
        return ciphertext

    @staticmethod
    def decrypt_data(encrypted: bytes, key: bytes, iv: bytes) -> bytes:
        aes = pyaes.AESModeOfOperationCTR(key, iv)
        plain = aes.decrypt(encrypted)
        return plain

if __name__ == '__main__':
    a = AesManager()
    data = b"f0cc186d01693a20b0540cc31bd792afee8c5231a6372cc37c3a6428247a0452"
    password = "00000000"
    passwordSalt = os.urandom(16)
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    iv = b'd78c79f302847de4e8b62f0ef087f6aa'
    iv1 = secrets.randbits(256)
    iv2 = pyaes.Counter(iv)
    print("iv1:", iv1)
    print("iv2:", iv2)
    print("key:", key)
    e = a.ecrypt_data(data, key, iv)  # 加密
    print("加密:", e)
    d = a.decrypt_data(e, b'9999999999999999', b'qqqqqqqqqqqqqqqq')  # 解密
    print("解密:", d)

