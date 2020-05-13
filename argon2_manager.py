#!/usr/bin/python3

import argon2
import binascii

MEMORYCOST = 20480
TIMECOST = 4
PARALLELIS = 2


class Argon2Manager:
    @staticmethod
    def hash(associated_data: bytes, salt: bytes):
        sp = salt + associated_data
        h = argon2.low_level.hash_secret_raw(sp, s, time_cost=4, memory_cost=20480, parallelism=2, hash_len=32, type=argon2.low_level.Type.ID)
        return binascii.b2a_hex(h).decode()

if __name__ == '__main__':
    ph = argon2.PasswordHasher(time_cost=4, memory_cost=20480, parallelism=2, hash_len=32, salt_len=16, encoding='utf-8', type=argon2.low_level.Type.ID)
    password = '00000000'
    print(ph.hash(password).encode())
    salt = '23d0927f83406a2b4593890b8e3775daa13a55905ace27bbdb0ffaaa0bc915e8'
    p = binascii.hexlify(password.encode())
    s = binascii.hexlify(salt.encode())
    ps = s + p
    print(s + p)
    a = argon2.low_level.hash_secret_raw(p, s, time_cost=4, memory_cost=20480, parallelism=2, hash_len=32, type=argon2.low_level.Type.ID)
    print(a)
    print(binascii.b2a_hex(a).decode())
