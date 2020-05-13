#!/usr/bin/python3

import argon2
import binascii

MEMORYCOST = 20480
TIMECOST = 4
PARALLELIS = 2


class Argon2Manager:
    @staticmethod
    def hash(associated_data: bytes, salt: bytes) -> bytes:
        sp = salt + associated_data
        h = argon2.low_level.hash_secret_raw(secret=sp, salt=salt, time_cost=TIMECOST, memory_cost=MEMORYCOST, parallelism=PARALLELIS, hash_len=32, type=argon2.low_level.Type.ID)
        return binascii.b2a_hex(h)


if __name__ == '__main__':
    password = '00000000'
    sa = '23d0927f83406a2b4593890b8e3775daa13a55905ace27bbdb0ffaaa0bc915e8'
    p = password.encode("utf8")#binascii.hexlify(password.encode())
    s = sa.encode("utf8") #binascii.hexlify(salt.encode())
    ps = s + p
    b = argon2.low_level.hash_secret_raw(secret=s + p, salt=s, time_cost=4, memory_cost=20480, parallelism=2, hash_len=32, type=argon2.low_level.Type.ID)
    print(s + p)
    print(Argon2Manager.hash(p, s))
    print(binascii.b2a_hex(b).decode())
