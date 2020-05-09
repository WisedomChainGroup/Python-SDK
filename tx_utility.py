#!/usr/bin/python3

from utils import Utils
from ed25519 import Ed25519PrivateKey
from sha3_keccak import Sha3Keccack
import binascii
import nacl.signing
from _pysha3 import keccak_256

GAS_TABLE = [0, 50000]

FEE = 2000000

TRANSFER = 1
DEFAULT_VERSION = 1


class Transaction:
    def __init__(self, tx_from: bytes = b'', gas_price: int = 0, version: int = DEFAULT_VERSION, tx_type: int = 0,
                 tx_nonce: int = 0, tx_amount: int = 0, payload: bytes = b'', tx_to: bytes = b'', sig: bytes = b''):
        self.version = version
        self.tx_type = tx_type
        self.tx_nonce = tx_nonce
        self.tx_from = tx_from
        self.gas_price = gas_price
        self.version = version
        self.tx_amount = tx_amount
        self.payload = payload
        self.tx_to = tx_to
        self.sig = sig

    def _get_raw(self, null_sig: bool) -> bytes:
        sig = b''
        if not null_sig:
            sig = self.sig
        ret = Utils.encode_u64(self.version)
        ret += Utils.encode_u64(self.tx_type)
        ret += Utils.encode_u64(self.tx_nonce)
        ret += self.tx_from
        ret += Utils.encode_u64(self.gas_price)
        ret += Utils.encode_u64(self.tx_amount)
        ret += sig
        ret += self.tx_to
        ret += Utils.encode_u64(len(self.payload))
        ret += self.payload
        return ret

    def get_raw_for_sign(self) -> bytes:
        return self._get_raw(True)

    def get_raw_for_hash(self) -> bytes:
        return self._get_raw(False)

    def get_hash(self) -> bytes:
        k = keccak_256()
        k.update(self.get_raw_for_hash())
        sks = k.hexdigest()
        return binascii.a2b_hex(sks)


class TxUtility:

    def __init__(self):
        self.serviceCharge = 200000
        self.rate = 100000000

    @staticmethod
    def sign_transaction(tx: Transaction, sk: bytes):
        tx.sig = nacl.signing.SigningKey(sk).sign(tx.get_raw_for_sign())

    # 构建签名事务
    def sign_tx(self, RawTransactionHex, prikeyStr):
        try:
            util = Utils()
            sha3Keccack = Sha3Keccack()
            RawTransaction = binascii.a2b_hex(RawTransactionHex)
            # 私钥字节数组
            privkey = binascii.a2b_hex(prikeyStr)
            # version
            version = util.byte_array_copy(RawTransaction, 0, 1)
            # type
            type = util.byte_array_copy(RawTransaction, 1, 1)
            # nonce
            nonce = util.byte_array_copy(RawTransaction, 2, 8)
            # from
            form = util.byte_array_copy(RawTransaction, 10, 32)
            # gasprice
            gasprice = util.byte_array_copy(RawTransaction, 42, 8)
            # amount
            amount = util.byte_array_copy(RawTransaction, 50, 8)
            # signo
            signo = util.byte_array_copy(RawTransaction, 58, 64)
            # to
            to = util.byte_array_copy(RawTransaction, 122, 20)
            # payloadlen
            payloadlen = util.byte_array_copy(RawTransaction, 142, 4)
            # payload
            payload = util.byte_array_copy(RawTransaction, 146, util.decode_u32(payloadlen))
            RawTransactionNoSign = version + type + nonce + form + gasprice + amount + signo + to + payloadlen + payload
            RawTransactionNoSig = version + type + nonce + form + gasprice + amount
            # 签名数据
            ed25519PrivateKey = Ed25519PrivateKey(privkey)
            sig = ed25519PrivateKey.sign(RawTransactionNoSign)
            transha = sha3Keccack.keccak256(RawTransactionNoSig + sig + to + payloadlen + payload)
            signRawBasicTransaction = version + transha + type + nonce + form + gasprice + amount + sig + to + payloadlen + payload
            signRawBasicTransactionHex = binascii.b2a_hex(signRawBasicTransaction)
            return signRawBasicTransactionHex.decode()
        except (OSError, TypeError) as reason:
            print('错误的原因是:', str(reason))

    def ClientToTransferAccount(self, fromPubkeyStr, toPubkeyHashStr, amount, prikeyStr, nonce):
        try:
            print('000')
            RawTransactionHex = TxUtility.create_transfer_tx(fromPubkeyStr, toPubkeyHashStr, amount, nonce)
            print('111', type(RawTransactionHex), RawTransactionHex)
            signRawBasicTransaction = binascii.a2b_hex(TxUtility.sign_tx(RawTransactionHex, prikeyStr))
            hash = Utils.byte_array_copy(signRawBasicTransaction, 1, 32)
            txHash = binascii.b2a_hex(hash).decode()
            traninfo = binascii.b2a_hex(signRawBasicTransaction).decode()
        except (OSError, TypeError) as reason:
            return ''

    # 构造交易事务
    def create_transfer_tx(self, tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int) -> Transaction:
        tx = Transaction()
        # 类型：WDC转账
        tx.tx_type = TRANSFER
        # Nonce 无符号64位
        tx.nonce = tx_nonce
        # 签发者公钥哈希 20字节
        tx.tx_from = tx_from
        tx.tx_to = tx_to
        tx.gas_price = FEE / GAS_TABLE[TRANSFER]
        # 转账金额 无符号64位
        tx.tx_amount = tx_amount
        return tx


if __name__ == '__main__':
    fromPubkeyStr = 'e872bbcb080c61608d0260d5b6cc7a73c8b89c446365132197aa84679bddd3d1'
    toPubkeyHashStr = '0d5babadfba67318fce816e3ebf27d727808c98f'
    amount = 10
    prikeyStr = '12Ddbt4bo7qqyfHcP9ApJQDcdWRBnBZzHo'
    nonce = 10
    b = TxUtility()
    print('1')
    # a = b.ClientToTransferAccount(fromPubkeyStr, toPubkeyHashStr, amount, prikeyStr, nonce)
    a = b.create_transfer_tx(fromPubkeyStr, toPubkeyHashStr, amount, nonce)
    print(type(a))
    print(a)
