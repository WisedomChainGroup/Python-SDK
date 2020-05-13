#!/usr/bin/python3

from key_pair import KeyStore, KeyPair
from argon2_manager import Argon2Manager
from aes_manager import AesManager
import secrets
import binascii


class WalletUtility:
    @staticmethod
    def from_password(password: str):
        keypair = KeyPair()
        salt = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        a = KeyStore()
        return a.__dict__


if __name__ == '__main__':
    p = "00000000"
    keypair = KeyPair()
    pk = keypair.public_key
    sk = keypair.secret_key
    print(sk)
    salt = binascii.b2a_hex(secrets.token_bytes(32))
    iv = binascii.b2a_hex(secrets.token_bytes(16))
    argon2id = Argon2Manager().hash(p.encode(), salt)
    print(pk)
    print(argon2id)
    aes = AesManager().ecrypt_data(binascii.a2b_hex(pk), binascii.a2b_hex(argon2id), binascii.a2b_hex(iv))
    print(aes)

