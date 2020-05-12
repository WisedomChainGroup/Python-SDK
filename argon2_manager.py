#!/usr/bin/python3

import argon2

MEMORYCOST = 20480
TIMECOST = 4
PARALLELIS = 2


class Argon2Manager:
    @staticmethod
    def hash(associated_data: bytes, salt: bytes):
        argon2.low_level.hash_secret(associated_data+salt, salt, time_cost=TIMECOST, memory_cost=MEMORYCOST, parallelism=PARALLELIS, hash_len=hash_len, type=argon2.low_level.Type.D)
        hash_len = 32
        ph = PasswordHasher(time_cost=TIMECOST, memory_cost=MEMORYCOST, parallelism=PARALLELIS, hash_len=hash_len, salt_len=len(salt))
        ph.hash("s3kr3tp4ssw0rd")
        c_out = ffi.new("uint8_t[]", hash_len)
        c_pwd = ffi.new("uint8_t[]", associated_data)
        c_salt = ffi.new("uint8_t[]", salt)
        ctx = ffi.new(
            "argon2_context *",
            dict(
                version=ARGON2_VERSION,
                out=c_out,
                outlen=hash_len,
                pwd=c_pwd,
                pwdlen=len(pwd),
                salt=c_salt,
                saltlen=len(salt),
                secret=ffi.NULL,
                secretlen=0,
                ad=ffi.NULL,
                adlen=0,
                t_cost=TIMECOST,
                m_cost=8,
                lanes=1,
                threads=1,
                allocate_cbk=ffi.NULL,
                free_cbk=ffi.NULL,
                flags=lib.ARGON2_DEFAULT_FLAGS,
            )
        )

        core(ctx, Type.D.value)
        out = bytes(ffi.buffer(ctx.out, ctx.outlen))
        out == argon2.low_level.hash_secret_raw(pwd, salt, 1, 8, 1, 8, Type.D)


if __name__ == '__main__':
    password = '123456789'
    salt = '6c5cb2b41b0945b1d1467c52cf95457fa865a0aa7d69ada77eccec31728316b9'
    ph = argon2.PasswordHasher(time_cost=TIMECOST, memory_cost=MEMORYCOST, parallelism=PARALLELIS, hash_len=32, salt_len=len(salt))
    print(ph.hash(password))