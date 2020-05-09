#!/usr/bin/python3

from PYSDK.Utils import Utils
from PYSDK.Ed25519PrivateKey import Ed25519PrivateKey
from PYSDK.Sha3Keccack import Sha3Keccack
from PYSDK.APIResult import APIResult
import binascii
import json

class TxUtility:

    def __init__(self):
        self.serviceCharge = 200000
        self.rate = 100000000

    # 构建签名事务
    def signRawBasicTransaction(self, RawTransactionHex, prikeyStr):
        try:
            RawTransaction = binascii.a2b_hex(RawTransactionHex)
            # 私钥字节数组
            privkey = binascii.a2b_hex(prikeyStr)
            # version
            version = Utils.bytearraycopy(RawTransaction, 0, 1)
            # type
            type = Utils.bytearraycopy(RawTransaction, 1, 1)
            # nonce
            nonce = Utils.bytearraycopy(RawTransaction, 2, 8)
            # from
            form = Utils.bytearraycopy(RawTransaction, 10, 32)
            # gasprice
            gasprice = Utils.bytearraycopy(RawTransaction, 42, 8)
            # amount
            amount = Utils.bytearraycopy(RawTransaction, 50, 8)
            # signo
            signo = Utils.bytearraycopy(RawTransaction, 58, 64)
            # to
            to = Utils.bytearraycopy(RawTransaction, 122, 20)
            # payloadlen
            payloadlen = Utils.bytearraycopy(RawTransaction, 142, 4)
            # payload
            payload = Utils.bytearraycopy(RawTransaction, 146, Utils.decodeUint32(payloadlen))
            RawTransactionNoSign = version + type + nonce + form + gasprice + amount + signo + to + payloadlen + payload
            RawTransactionNoSig = version + type + nonce + form + gasprice + amount
            # 签名数据
            sig = Ed25519PrivateKey(privkey).sign(RawTransactionNoSign);
            transha = Sha3Keccack.keccak256(RawTransactionNoSig + sig + to + payloadlen + payload)
            signRawBasicTransaction = version + transha + type + nonce + form + gasprice + amount + sig + to + payloadlen + payload
            signRawBasicTransactionHex = binascii.b2a_hex(signRawBasicTransaction)
            return signRawBasicTransactionHex.decode()
        except (OSError, TypeError) as reason:
            print('错误的原因是:', str(reason))

    def ClientToTransferAccount(self, fromPubkeyStr, toPubkeyHashStr, amount, prikeyStr, nonce):
        try:
            print('000')
            RawTransactionHex = TxUtility.CreateRawTransaction(fromPubkeyStr, toPubkeyHashStr, amount, nonce)
            print('111', type(RawTransactionHex), RawTransactionHex)
            signRawBasicTransaction = binascii.a2b_hex(TxUtility.signRawBasicTransaction(RawTransactionHex, prikeyStr))
            hash = Utils.bytearraycopy(signRawBasicTransaction, 1, 32)
            txHash = binascii.b2a_hex(hash).decode()
            traninfo = binascii.b2a_hex(signRawBasicTransaction).decode()
            Result = APIResult(txHash, traninfo)
            return json.dumps(Result.__dict__)
        except (OSError, TypeError) as reason:
            return ''

    # 构造交易事务
    def CreateRawTransaction(self, fromPubkeyStr, toPubkeyHashStr, amount, nonce):
        try:
            util = Utils()
            # 版本号
            version = bytes('0x01', 'utf8')
            # 类型：WDC转账
            type = bytes('0x01', 'utf8')
            # Nonce 无符号64位
            nonece = util.encodeUint64(nonce + 1)
            # 签发者公钥哈希 20字节
            fromPubkeyHash = binascii.a2b_hex(fromPubkeyStr)
            # gas单价
            gasPrice = util.encodeUint64(round(50000 / self.serviceCharge))
            # 转账金额 无符号64位
            bdAmount = amount * self.rate
            Amount = util.encodeUint64(bdAmount)
            # 为签名留白
            list = ['0' for x in range(0, 64)]
            signull = binascii.a2b_hex(''.join(list))
            # 接收者公钥哈希
            toPubkeyHash = binascii.a2b_hex(toPubkeyHashStr)
            # 长度
            allPayload = util.encodeUint32(0)
            RawTransaction = version + type + nonece + fromPubkeyHash + gasPrice + Amount + signull+toPubkeyHash+allPayload
            RawTransactionStr = binascii.b2a_hex(RawTransaction).decode()
            return RawTransactionStr
        except (OSError, TypeError) as reason:
            return ''


if __name__ == '__main__':
    fromPubkeyStr = 'e872bbcb080c61608d0260d5b6cc7a73c8b89c446365132197aa84679bddd3d1'
    toPubkeyHashStr = '0d5babadfba67318fce816e3ebf27d727808c98f'
    amount = 10
    prikeyStr = '12Ddbt4bo7qqyfHcP9ApJQDcdWRBnBZzHo'
    nonce = 10
    b = TxUtility()
    print('1')
    #a = b.ClientToTransferAccount(fromPubkeyStr, toPubkeyHashStr, amount, prikeyStr, nonce)
    a = b.CreateRawTransaction(fromPubkeyStr, toPubkeyHashStr, amount, nonce)
    print(type(a))
    print(a)
