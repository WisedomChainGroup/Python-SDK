#!/usr/bin/python3

from utils import Utils
from ed25519 import Ed25519PrivateKey
from sha3_keccak import Sha3Keccack
import binascii
import nacl.signing
from _pysha3 import keccak_256

GAS_TABLE = [0, 50000]
FEE = 200000
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
        sig = bytes(64)
        if not null_sig:
            sig = self.sig
        ret = Utils.encode_u8(self.version)
        ret += Utils.encode_u8(self.tx_type)
        ret += Utils.encode_u64(self.tx_nonce)
        ret += self.tx_from
        ret += Utils.encode_u64(self.gas_price)
        ret += Utils.encode_u64(self.tx_amount)
        ret += sig
        ret += self.tx_to
        ret += Utils.encode_u32(len(self.payload))
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

    @staticmethod
    def sign_transaction(tx: Transaction, sk: bytes):
        tx.sig = nacl.signing.SigningKey(sk).sign(tx.get_raw_for_sign())[0:-len(tx.get_raw_for_sign())]

    # 构造交易事务
    @staticmethod
    def create_transfer_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int) -> Transaction:
        tx = Transaction(
            tx_type=TRANSFER,
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount
        )
        tx.gas_price = round(FEE / GAS_TABLE[TRANSFER])
        return tx


if __name__ == '__main__':
    fromPubkeyStr = binascii.a2b_hex('7a94e5c3c8bf9bbf23df6d195ff3a76322088a94886f5bfee70ac574d11bd52a')
    toPubkeyHashStr = binascii.a2b_hex('0d5babadfba67318fce816e3ebf27d727808c98f')
    amount = 10 * 100000000
    prikeyStr = binascii.a2b_hex('f0d55ae8a79186e8595514fe23dec8716a191d2bb525998298371693dc69a926')
    nonce = 2
    a = TxUtility()
    b = a.create_transfer_tx(fromPubkeyStr, toPubkeyHashStr, amount, nonce)
    print('b.sig:' + binascii.b2a_hex(b.sig).decode())
    a.sign_transaction(b, prikeyStr)
    print('b.sig:' + binascii.b2a_hex(b.sig).decode())
    print('b.get_raw_for_sign:' + binascii.b2a_hex(b.get_raw_for_sign()).decode())
    print('b.get_hash:' + binascii.b2a_hex(b.get_hash()).decode())
    print('b.get_raw_for_hash:' + binascii.b2a_hex(b.get_raw_for_hash()).decode()[0:2] + binascii.b2a_hex(b.get_hash()).decode() + binascii.b2a_hex(b.get_raw_for_hash()).decode()[2:])


