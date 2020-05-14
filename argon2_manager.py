#!/usr/bin/python3

import argon2
import binascii


class Argon2Manager:

    @staticmethod
    def hash(associated_data: bytes, salt: bytes, time_cost: int, memory_cost: int, parallelism: int) -> bytes:
        sp = salt + associated_data
        h = argon2.low_level.hash_secret_raw(secret=sp, salt=salt, time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism, hash_len=32, type=argon2.low_level.Type.ID)
        return binascii.b2a_hex(h)


if __name__ == '__main__':
    password = '00000000'
    sa = '23d0927f83406a2b4593890b8e3775daa13a55905ace27bbdb0ffaaa0bc915e8'
    p = password.encode("utf8")
    s = sa.encode("utf8")
    print(Argon2Manager.hash(p, s, 4, 20480, 2))

