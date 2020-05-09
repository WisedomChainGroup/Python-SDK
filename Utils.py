#!/usr/bin/python3

import numpy as np
import binascii

class Utils:

    def bytearraycopy(self, s, start, count):
        r = s[start:count + start]
        return r

    def decodeUint32(self, data):
        r = int.from_bytes(data, byteorder='big', signed=False)
        return r

    def encodeUint64(self, data):
        r = (data).to_bytes(8, 'big')
        return r

if __name__ == '__main__':
    sks = binascii.a2b_hex("9a90128b52960688cc67ba76a04088aa90525c35abc2282acfa72f6c0eedef5f")
    a = Utils()
    sk = a.bytearraycopy(sks, 142, 4)
    skd = binascii.b2a_hex(a.encodeUint64(11)).decode()
    print('a', skd, len(skd))

