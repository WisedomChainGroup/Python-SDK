#!/usr/bin/python3

import binascii

from Crypto.Cipher import AES
from Crypto.Util import Counter

MODEL = AES.MODE_CTR


class AesManager:
    @staticmethod
    def __int_of_string(s):
        return int(binascii.hexlify(s), 16)

    @staticmethod
    def encrypt_data(plain: bytes, key: bytes, iv: bytes) -> bytes:
        ctr = Counter.new(128, initial_value=AesManager.__int_of_string(iv))
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        result = aes.encrypt(plain)
        return binascii.b2a_hex(result)

    @staticmethod
    def decrypt_data(encrypted: bytes, key: bytes, iv: bytes) -> bytes:
        ctr = Counter.new(128, initial_value=AesManager.__int_of_string(iv))
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        result = aes.decrypt(encrypted)
        return result


if __name__ == '__main__':
    i = b"59140a7f3e19e8b94a11dd0951c6c35c"
    pk = b"89c8181609a202ca4ee15d6602bb3adb0cae164f8f38e547b4240d0a01b84bd5"
    print(binascii.a2b_hex(i))
    a = int(binascii.hexlify(binascii.a2b_hex(i)), 16)
    print(a, type(a))
    counter = Counter.new(128, initial_value=a)
    print(counter)
    k = binascii.a2b_hex(b"7cfc6d1f2444a9aba9da9d5e3cdc3d7e7901222d9bb4a79b7a2f027721ce4c04")
    crypto = AES.new(k, AES.MODE_CTR, counter=counter)
    ex = binascii.a2b_hex(pk)
    plains = crypto.encrypt(ex)
    print(binascii.b2a_hex(plains))
    print(AesManager.encrypt_data(ex, k, binascii.a2b_hex(i)))
