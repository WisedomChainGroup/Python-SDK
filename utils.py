#!/usr/bin/python3

import binascii


class Utils:
    @staticmethod
    def byte_array_copy(s, start, count):
        r = s[start:count + start]
        return r

    @staticmethod
    def decode_u32(data):
        r = int.from_bytes(data, byteorder='big', signed=False)
        return r

    @staticmethod
    def encode_u64(data: int) -> bytes:
        if data < 0:
            raise str(data) + 'is negative'
        r = data.to_bytes(8, 'big')
        return r

    @staticmethod
    def encode_u32(data: int) -> bytes:
        if data < 0:
            raise str(data) + 'is negative'
        r = data.to_bytes(4, 'big')
        return r

    @staticmethod
    def encode_u8(data: int) -> bytes:
        if data < 0:
            raise str(data) + 'is negative'
        r = data.to_bytes(1, 'big')
        return r


if __name__ == '__main__':
    sks = binascii.a2b_hex("9a90128b52960688cc67ba76a04088aa90525c35abc2282acfa72f6c0eedef5f")
    sk = Utils.byte_array_copy(sks, 142, 4)
    skd = binascii.b2a_hex(Utils.encode_u64(round(100000 / 200000))).decode()
    print('a', skd)
    print(binascii.b2a_hex(Utils.encode_u64(255)))