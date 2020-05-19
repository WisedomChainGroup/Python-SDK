#!/usr/bin/python3

from utils import Utils
import nacl.signing

GAS_TABLE = [0, 50000, 100000, 20000]
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
        return Utils.keccak256(self.get_raw_for_hash())


class TxUtility:

    @staticmethod
    def sign_transaction(tx: Transaction, sk: bytes):
        tx.sig = nacl.signing.SigningKey(sk).sign(tx.get_raw_for_sign())[0:-len(tx.get_raw_for_sign())]

    @staticmethod
    def create_transfer_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int) -> Transaction:
        """
            构造交易事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: bytes
            :param tx_nonce: bytes
            :return: Transaction
        """
        tx = Transaction(
            tx_type=TRANSFER,
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount
        )
        tx.gas_price = round(FEE / GAS_TABLE[TRANSFER])
        return tx

    @staticmethod
    def create_transfer_vote_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int) -> Transaction:
        """
            构造投票事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: int
            :param tx_nonce: int
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type=2,
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount
        )
        tx.gas_price = round(FEE / GAS_TABLE[3])
        return tx

    @staticmethod
    def create_transfer_vote_with_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int, tx_id: bytes) -> Transaction:
        """
            构造投票事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: int
            :param tx_nonce: int
            :param tx_id: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type=13,
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount,
            payload=tx_id,
        )
        tx.gas_price = round(FEE / GAS_TABLE[3])
        return tx

    @staticmethod
    def create_transfer_mortgage_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int) -> Transaction:
        """
            构造抵押事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: int
            :param tx_nonce: int
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type=14,
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount,
        )
        tx.gas_price = round(FEE / GAS_TABLE[3])
        return tx

    @staticmethod
    def create_transfer_mortgage_with_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int, tx_id: bytes) -> Transaction:
        """
            构造抵押事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: int
            :param tx_nonce: int
            :param tx_id: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type=14,
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount,
            payload=tx_id,
        )
        tx.gas_price = round(FEE / GAS_TABLE[3])
        return tx

    @staticmethod
    def create_transfer_prove_with_tx(tx_from: bytes, tx_to: bytes, tx_amount: int, tx_nonce: int) -> Transaction:
        """
            构造存证事务
            :param tx_from: bytes
            :param tx_to: bytes
            :param tx_amount: int
            :param tx_nonce: int
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type=3,
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=tx_to,
            tx_amount=tx_amount
        )
        tx.gas_price = round(FEE / GAS_TABLE[2])
        return tx

    @staticmethod
    def create_transfer_deploy_for_rule_asset_tx(tx_from: bytes, tx_nonce: int, tx_code: str, tx_offering: int, tx_total_amount: int, tx_create_user: bytes, tx_owner: bytes, tx_allow_increase: int, tx_info: bytes) -> Transaction:
        """
            部署资产定义事务
            :param tx_from: bytes
            :param tx_nonce: int
            :param tx_code: str
            :param tx_offering: int
            :param tx_total_amount: int
            :param tx_create_user: bytes
            :param tx_owner: bytes
            :param tx_allow_increase: int
            :param tx_info: bytes
            :return: Transaction
        """
        tx = Transaction(
            version=1,
            tx_type=7,
            tx_nonce=tx_nonce,
            tx_from=tx_from,
            tx_to=b"0000000000000000000000000000000000000000",
            tx_amount=0
        )
        tx.gas_price = round(FEE / GAS_TABLE[2])
        return tx

if __name__ == '__main__':
    # fromPubkey = bytes.fromhex('7a94e5c3c8bf9bbf23df6d195ff3a76322088a94886f5bfee70ac574d11bd52a')
    # toPubkeyHash = bytes.fromhex('fbdacd374729b74c594cf955dc207fbb1d203a10')
    # amount = 10 * 100000000
    # prikey = bytes.fromhex('f0d55ae8a79186e8595514fe23dec8716a191d2bb525998298371693dc69a926')
    fromPubkey = bytes.fromhex('fce8ec82c17bbd763e2edfbbd9ae9cb24bfa2181e166c4c8590435c6383a4465')
    toPubkeyHash = bytes.fromhex('a8dab9a3828d750174c25f09ab619f55d7533346')
    amount = 10 * 100000000
    prikey = bytes.fromhex('a4643462e43c642418f638d5cb0ba7bf79d3887e7df0e146a0a7a1738eef0107')
    nonce = 1
    a = TxUtility()
    b = a.create_transfer_tx(fromPubkey, toPubkeyHash, amount, nonce)
    print('b.sig: ' + b.sig.hex())
    print('b.get_raw_for_sign: ' + b.get_raw_for_sign().hex())
    a.sign_transaction(b, prikey)
    print('b.sig: ' + b.sig.hex())
    print('b.get_hash: ' + b.get_hash().hex())
    print('b.get_raw_for_hash: ' + b.get_raw_for_hash().hex())
